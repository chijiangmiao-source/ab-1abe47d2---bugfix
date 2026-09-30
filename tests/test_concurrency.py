"""End-to-end concurrency tests for same-id simultaneous submissions.

A real uvicorn server runs in-process; the engine is gated behind an event
so the winner's computation provably overlaps the losers' wait.  FastAPI
runs the sync endpoint in a worker thread pool, so the losers really do
park on the store's condition variable rather than returning an early
"processing" response.
"""

from __future__ import annotations

import copy
import socket
import threading
import time
import uuid

import httpx
import pytest
import uvicorn

import app.main as main_mod
from app.main import app


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def base_url():
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            if httpx.get(url + "/healthz", timeout=1).status_code == 200:
                break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("test server failed to start")
    yield url
    server.should_exit = True
    thread.join(5)


@pytest.fixture
def gated_analyze(monkeypatch):
    """Slow the winner's verdict computation until the test releases it."""
    real_analyze = main_mod.analyze
    state = {"entered": 0}
    entered = threading.Event()
    release = threading.Event()

    def slow_analyze(rules):
        state["entered"] += 1
        entered.set()
        assert release.wait(5), "winner was never released"
        return real_analyze(rules)

    monkeypatch.setattr(main_mod, "analyze", slow_analyze)
    yield entered, release, state
    release.set()


def fresh_audit_id() -> str:
    return "c-" + uuid.uuid4().hex[:12]


def overlapping_payload(audit_id: str, n: int = 18) -> dict:
    """~18 legal rules whose networks and port ranges overlap heavily."""
    rules = []
    for i in range(n):
        rules.append(
            {
                "id": f"r{i + 1}",
                "protocol": "both" if i % 3 == 0 else "tcp",
                "src_cidr": "10.0.0.0/24" if i % 2 == 0 else "10.0.0.0/25",
                "dst_cidr": "192.168.0.0/24",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80 + (i % 5), "end": 90 + (i % 7)},
            }
        )
    return {"audit_id": audit_id, "rules": rules}


def tampered(payload: dict, end: int) -> dict:
    other = copy.deepcopy(payload)
    other["rules"][-1]["dst_port"]["end"] = end
    return other


def post_json(url: str, payload: dict) -> tuple[int, dict]:
    resp = httpx.post(url, json=payload, timeout=15)
    try:
        return resp.status_code, resp.json()
    except Exception:
        return resp.status_code, {"raw": resp.text}


def settle(gated_analyze, wave_threads):
    """Let the winner finish once every request has had time to park."""
    entered, release, state = gated_analyze
    assert entered.wait(2), "no request entered verdict computation"
    time.sleep(0.5)  # the other requests arrive and block on the store
    release.set()
    for thread in wave_threads:
        thread.join(15)


class TestConcurrentIdenticalPayload:
    def test_single_frozen_conclusion_everybody_replays_it(
        self, base_url, gated_analyze
    ):
        audit_id = fresh_audit_id()
        payload = overlapping_payload(audit_id)
        copies = [copy.deepcopy(payload) for _ in range(4)]

        threads_results = {}
        barrier = threading.Barrier(len(copies))

        def worker(index: int) -> None:
            barrier.wait()
            resp = httpx.post(
                base_url + "/api/audits", json=copies[index], timeout=15
            )
            threads_results[index] = (resp.status_code, resp.json())

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        entered, release, state = gated_analyze
        assert entered.wait(2)
        time.sleep(0.5)
        # While the winner computes, nobody may have seen a verdict yet and
        # there is exactly one computation.
        assert threads_results == {}
        assert state["entered"] == 1
        release.set()
        for thread in threads:
            thread.join(15)

        statuses = sorted(threads_results[i][0] for i in range(4))
        assert statuses == [200, 200, 200, 201]
        assert 202 not in statuses
        bodies = [threads_results[i][1] for i in range(4)]
        assert all(body == bodies[0] for body in bodies)
        assert len(bodies[0]["verdicts"]) == 18
        # No "processing" placeholder shape ever leaks.
        assert all("verdicts" in body for body in bodies)

        frozen = httpx.get(base_url + f"/api/audits/{audit_id}", timeout=5)
        assert frozen.status_code == 200
        assert frozen.json() == bodies[0]


class TestConcurrentDifferentPayloads:
    def test_conflicts_store_nothing_and_winner_freezes(
        self, base_url, gated_analyze
    ):
        audit_id = fresh_audit_id()
        payload = overlapping_payload(audit_id)
        payloads = [
            copy.deepcopy(payload),
            tampered(payload, 500),
            tampered(payload, 600),
            tampered(payload, 700),
        ]

        results: list[tuple[int, dict] | None] = [None] * 4
        barrier = threading.Barrier(4)

        def worker(index: int) -> None:
            barrier.wait()
            results[index] = post_json(base_url + "/api/audits", payloads[index])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for thread in threads:
            thread.start()
        settle(gated_analyze, threads)

        statuses = [results[i][0] for i in range(4)]
        assert sorted(statuses) == [201, 409, 409, 409], statuses
        winner_index = statuses.index(201)
        winning_payload = payloads[winner_index]
        for i in range(4):
            if statuses[i] == 409:
                assert results[i][1]["detail"]["error"] == "audit_id_conflict"

        frozen = httpx.get(base_url + f"/api/audits/{audit_id}", timeout=5)
        assert frozen.status_code == 200
        assert frozen.json()["rules"] == winning_payload["rules"]
        assert frozen.json() == results[winner_index][1]

        # A later sequential conflicting replay is still rejected and still
        # leaves the frozen conclusions untouched.
        again = httpx.post(
            base_url + "/api/audits",
            json=tampered(winning_payload, 12345),
            timeout=5,
        )
        assert again.status_code == 409
        after = httpx.get(base_url + f"/api/audits/{audit_id}", timeout=5)
        assert after.json()["rules"] == winning_payload["rules"]


class TestClaimantFailure:
    def test_failed_claimant_releases_slot_and_leaves_no_record(
        self, base_url, monkeypatch
    ):
        audit_id = fresh_audit_id()
        payload = overlapping_payload(audit_id)
        real_analyze = main_mod.analyze
        calls = {"n": 0}
        entered = threading.Event()
        release = threading.Event()

        def flaky_analyze(rules):
            calls["n"] += 1
            if calls["n"] == 1:
                entered.set()
                raise RuntimeError("boom")
            assert release.wait(5)
            return real_analyze(rules)

        monkeypatch.setattr(main_mod, "analyze", flaky_analyze)

        payloads = [copy.deepcopy(payload) for _ in range(3)]
        results: list[tuple[int, dict] | None] = [None] * 3
        barrier = threading.Barrier(3)

        def worker(index: int) -> None:
            barrier.wait()
            results[index] = post_json(base_url + "/api/audits", payloads[index])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(3)]
        for thread in threads:
            thread.start()
        assert entered.wait(2)
        # First claimant fails; another thread must claim and now block here.
        time.sleep(0.5)
        release.set()
        for thread in threads:
            thread.join(15)

        statuses = sorted(results[i][0] for i in range(3))
        assert statuses == [200, 201, 500], statuses
        success_bodies = [
            results[i][1] for i in range(3) if results[i][0] in (200, 201)
        ]
        assert success_bodies[0] == success_bodies[1]
        assert len(success_bodies[0]["verdicts"]) == 18

        frozen = httpx.get(base_url + f"/api/audits/{audit_id}", timeout=5)
        assert frozen.status_code == 200
        assert frozen.json() == success_bodies[0]


class TestConcurrentMixedWave:
    def test_create_replay_conflict_in_one_wave(self, base_url, gated_analyze):
        audit_id = fresh_audit_id()
        payload_a = overlapping_payload(audit_id)
        payload_b = tampered(payload_a, 999)
        payloads = [
            copy.deepcopy(payload_a),
            copy.deepcopy(payload_a),
            copy.deepcopy(payload_a),
            copy.deepcopy(payload_b),
            copy.deepcopy(payload_b),
        ]

        results: list[tuple[int, dict] | None] = [None] * 5
        barrier = threading.Barrier(5)

        def worker(index: int) -> None:
            barrier.wait()
            results[index] = post_json(base_url + "/api/audits", payloads[index])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for thread in threads:
            thread.start()
        settle(gated_analyze, threads)

        winners = [i for i in range(5) if results[i][0] == 201]
        assert len(winners) == 1
        winner_index = winners[0]
        frozen_body = results[winner_index][1]

        # Whichever payload won, assertions are scheduled against it.
        if winner_index < 3:
            replay_indices = [i for i in range(3) if i != winner_index]
            conflict_indices = [3, 4]
            winning_payload = payload_a
        else:
            replay_indices = [3 if winner_index == 4 else 4]
            conflict_indices = [0, 1, 2]
            winning_payload = payload_b

        for i in replay_indices:
            assert results[i][0] == 200, results[i][0]
            assert results[i][1] == frozen_body  # byte-identical replay
        for i in conflict_indices:
            assert results[i][0] == 409, results[i][0]
            assert "verdicts" not in results[i][1]
        assert 202 not in [results[i][0] for i in range(5)]

        frozen = httpx.get(base_url + f"/api/audits/{audit_id}", timeout=5)
        assert frozen.status_code == 200
        assert frozen.json() == frozen_body
        assert frozen.json()["rules"] == winning_payload["rules"]
