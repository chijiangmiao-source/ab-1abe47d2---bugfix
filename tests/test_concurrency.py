"""Concurrency tests: same audit id submitted simultaneously.

The engine is paused until the expected follower threads have actually
entered the store rendezvous, so every racing request is genuinely in
flight while the leader computes.  These cases pin the freeze semantics:

* identical concurrent payloads collapse into one frozen conclusion -- one
  201, all other requests 200 with byte-identical complete responses (no
  provisional "processing" answer, no missing verdicts);
* a different payload racing under the same audit id gets 409, stores
  nothing, and never rewrites the winner's frozen conclusions.
"""

from __future__ import annotations

import json
import threading

import pytest
from fastapi import HTTPException

import app.main as main_module
from app.main import create_audit
from app.schemas import AuditRequest


def make_payload(audit_id: str, *, dp2_end: int = 90) -> dict:
    return {
        "audit_id": audit_id,
        "rules": [
            {
                "id": "r1",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/24",
                "dst_cidr": "192.168.0.0/24",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": 85},
            },
            {
                "id": "r2",
                "protocol": "tcp",
                "src_cidr": "10.0.0.128/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": dp2_end},
            },
            {
                "id": "r3",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 82, "end": 84},
            },
        ],
    }


def call_endpoint(payload: dict) -> tuple[int, dict]:
    """Invoke the POST handler in the calling thread; return (status, body)."""
    req = AuditRequest.model_validate(payload)
    try:
        resp = create_audit(req)
    except HTTPException as exc:
        detail = exc.detail
        return exc.status_code, detail if isinstance(detail, dict) else {"msg": detail}
    return resp.status_code, json.loads(resp.body)


@pytest.fixture
def gated_engine(monkeypatch):
    """Pause the leader until ``expected_followers`` same-payload followers
    are queued on the rendezvous, then let the analysis run.
    """
    real_analyze = main_module.analyze
    real_begin = main_module.store.begin

    def install(expected_followers: int) -> threading.Event:
        followers_ready = threading.Event()
        counter = {"n": 0}
        counter_lock = threading.Lock()

        def begin(audit_id, digest):
            existing, slot, is_leader = real_begin(audit_id, digest)
            if existing is None and slot is not None and not is_leader:
                with counter_lock:
                    counter["n"] += 1
                    if counter["n"] >= expected_followers:
                        followers_ready.set()
            return existing, slot, is_leader

        def gated(rules):
            assert followers_ready.wait(timeout=10), "跟随者未全部到达会合点"
            return real_analyze(rules)

        monkeypatch.setattr(main_module.store, "begin", begin)
        monkeypatch.setattr(main_module, "analyze", gated)
        return followers_ready

    return install


def run_racer(plan, results, results_lock, start):
    def worker(name, payload):
        start.wait()
        outcome = call_endpoint(payload)
        with results_lock:
            results[name] = outcome

    threads = [threading.Thread(target=worker, args=args) for args in plan]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads), "存在请求永久挂起"
    return threads


class TestConcurrentIdenticalPayload:
    def test_single_create_others_replay_identical(self, gated_engine):
        audit_id = "race-same-0001"
        payload = make_payload(audit_id)
        n = 8
        gated_engine(expected_followers=n - 1)

        results: dict[str, tuple[int, dict]] = {}
        lock = threading.Lock()
        start = threading.Barrier(n)
        plan = [(f"c{i}", payload) for i in range(n)]
        run_racer(plan, results, lock, start)

        statuses = {name: status for name, (status, _) in results.items()}
        created = [name for name, s in statuses.items() if s == 201]
        replayed = [name for name, s in statuses.items() if s == 200]
        assert len(created) == 1, statuses
        assert len(replayed) == n - 1, statuses

        winner_body = results[created[0]][1]
        assert winner_body["audit_id"] == audit_id
        assert len(winner_body["verdicts"]) == 3
        for name, (status, body) in results.items():
            assert body == winner_body, f"{name} 的响应与创建结论不一致"

        # A later sequential query returns the same frozen conclusions.
        frozen = main_module.store.get(audit_id)
        assert frozen is not None
        assert frozen.response() == winner_body

    def test_no_processing_response_ever(self, gated_engine):
        audit_id = "race-same-0002"
        payload = make_payload(audit_id)
        n = 6
        gated_engine(expected_followers=n - 1)

        results: dict[str, tuple[int, dict]] = {}
        lock = threading.Lock()
        start = threading.Barrier(n)
        run_racer([(f"c{i}", payload) for i in range(n)], results, lock, start)

        for name, (status, body) in results.items():
            assert status in (200, 201), (name, status)
            assert "verdicts" in body
            assert body.get("status") != "processing"


class TestConcurrentConflictingPayload:
    def test_foreign_payload_gets_409_and_winner_freezes(self, gated_engine):
        audit_id = "race-diff-0001"
        payload_a = make_payload(audit_id, dp2_end=90)
        payload_b = make_payload(audit_id, dp2_end=91)

        # The leader proceeds once its identical twin is queued as a
        # follower; the foreign-digest pair is rejected at the slot.
        gated_engine(expected_followers=1)

        results: dict[str, tuple[int, dict]] = {}
        lock = threading.Lock()
        start = threading.Barrier(4)
        plan = [("a1", payload_a), ("a2", payload_a), ("b1", payload_b), ("b2", payload_b)]
        run_racer(plan, results, lock, start)

        statuses = {name: status for name, (status, _) in results.items()}
        winners = [name for name, s in statuses.items() if s == 201]
        assert len(winners) == 1, statuses
        winner = winners[0]
        winner_payload = payload_a if winner.startswith("a") else payload_b
        winner_twin = ("a2" if winner == "a1" else "a1") if winner.startswith("a") else (
            "b2" if winner == "b1" else "b1"
        )
        losers = [name for name in ("a1", "a2", "b1", "b2") if not name.startswith(winner[0])]

        # The winner's identical twin replays the exact same response.
        assert statuses[winner_twin] == 200, statuses
        assert results[winner_twin][1] == results[winner][1]

        # Both requests carrying the other payload got a conflict.
        for name in losers:
            status, body = results[name]
            assert status == 409, (name, status)
            assert body["error"] == "audit_id_conflict"

        # Frozen record belongs to the winner payload; the loser left no
        # trace and cannot rewrite it.
        loser_payload = payload_b if winner_payload is payload_a else payload_a
        frozen = main_module.store.get(audit_id)
        assert frozen is not None
        assert frozen.response()["rules"] == winner_payload["rules"]
        assert frozen.response()["verdicts"] == results[winner][1]["verdicts"]

        # A later sequential submission of the loser payload is still 409.
        status, _ = call_endpoint(loser_payload)
        assert status == 409
        assert main_module.store.get(audit_id).response()["rules"] == winner_payload["rules"]

    def test_foreign_follower_rejected_without_waiting_for_leader(self, monkeypatch):
        """A different-payload racer is rejected immediately, instead of
        blocking until the leader's computation finishes."""
        real_analyze = main_module.analyze
        release = threading.Event()

        def slow(rules):
            assert release.wait(timeout=10), "测试夹具未释放"
            return real_analyze(rules)

        monkeypatch.setattr(main_module, "analyze", slow)

        audit_id = "race-diff-0002"
        payload_a = make_payload(audit_id, dp2_end=90)
        payload_b = make_payload(audit_id, dp2_end=91)
        outcomes: dict[str, tuple[int, dict]] = {}

        t_leader = threading.Thread(
            target=lambda: outcomes.setdefault("leader", call_endpoint(payload_a))
        )
        t_leader.start()
        # Race B once the leader has most likely entered analysis; either
        # way it must be rejected promptly.
        t_foreign = threading.Thread(
            target=lambda: outcomes.setdefault("foreign", call_endpoint(payload_b))
        )
        t_foreign.start()
        t_foreign.join(timeout=5)
        assert not t_foreign.is_alive(), "异载荷请求不应等待创建者完成"
        assert outcomes["foreign"][0] == 409

        release.set()
        t_leader.join(timeout=10)
        assert outcomes["leader"][0] == 201
        assert main_module.store.get(audit_id).response()["rules"] == payload_a["rules"]


class TestLeaderFailure:
    def test_follower_retries_when_leader_aborts(self, monkeypatch):
        """If the leader fails before committing, waiting followers are
        released and one of them creates the frozen conclusion."""
        real_analyze = main_module.analyze
        calls = {"n": 0}
        calls_lock = threading.Lock()

        def flaky(rules):
            with calls_lock:
                calls["n"] += 1
                if calls["n"] == 1:
                    raise RuntimeError("boom")
            return real_analyze(rules)

        monkeypatch.setattr(main_module, "analyze", flaky)

        audit_id = "race-abort-0001"
        payload = make_payload(audit_id)
        results: dict[str, tuple[int, dict]] = {}
        start = threading.Barrier(3)

        def worker(name):
            start.wait()
            try:
                results[name] = call_endpoint(payload)
            except RuntimeError as exc:
                results[name] = (500, {"error": type(exc).__name__})

        threads = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b", "c")]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        assert not any(t.is_alive() for t in threads), "跟随者因创建者失败而挂起"

        statuses = sorted(status for status, _ in results.values())
        # One request failed, the other two collapsed into one conclusion.
        assert statuses == [200, 201, 500], statuses
        winner = next(body for status, body in results.values() if status == 201)
        replay = next(body for status, body in results.values() if status == 200)
        assert replay == winner

        # The rendezvous slot was cleaned up: later traffic is a plain replay.
        assert call_endpoint(payload)[0] == 200
