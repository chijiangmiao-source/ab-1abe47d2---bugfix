"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, API, races)
  3. HTTP smoke    — against the live service: one partially shadowed rule,
                     one fully shadowed rule, and an illegal retransmission
                     (same audit id, different payload)
  4. HTTP concurrency — same audit id fired simultaneously with both
                        identical and different legal payloads (near the
                        18-rule limit, heavily overlapping): one frozen
                        conclusion, identical replays, 409 conflicts

Exits 0 only if every step passes; the Compose ``verify`` service surfaces
this as its container exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8080").rstrip("/")


def log(msg: str) -> None:
    print(msg, flush=True)


def sh(cmd: list[str]) -> bool:
    log(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode == 0


def build_check() -> bool:
    return sh([sys.executable, "-m", "compileall", "-q", "app", "verify", "tests"])


def code_tests() -> bool:
    return sh([sys.executable, "-m", "pytest", "-q", "tests"])


def http(method: str, path: str, body=None):
    """JSON request; returns (status, parsed_body_or_text)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        APP_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def wait_ready(timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = http("GET", "/healthz")
            if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def smoke() -> None:
    assert wait_ready(), f"服务在 {APP_URL} 上未通过健康检查"

    audit_id = f"smoke-{int(time.time())}"
    rules = [
        # r1: baseline rule.
        {"id": "r1", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}},
        # r2: partially shadowed by r1 — only dst ports 86..90 remain.
        {"id": "r2", "protocol": "tcp",
         "src_cidr": "10.0.0.128/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 90}},
        # r3: fully contained in r1 — never matches any packet.
        {"id": "r3", "protocol": "tcp",
         "src_cidr": "10.0.0.0/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 82, "end": 84}},
    ]

    status, body = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 201, f"创建审计失败: HTTP {status} {body}"
    verdicts = {v["rule_id"]: v for v in body["verdicts"]}

    v1 = verdicts["r1"]
    assert v1["status"] == "hit" and v1["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.0", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 80,
    }, f"r1 结论错误: {v1}"

    v2 = verdicts["r2"]
    assert v2["status"] == "hit" and v2["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.128", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 86,
    }, f"部分遮蔽的 r2 结论或最小见证错误: {v2}"

    v3 = verdicts["r3"]
    assert v3["status"] == "shadowed" and v3["covered_by"] == ["r1"], (
        f"完全遮蔽的 r3 结论或覆盖集合错误: {v3}"
    )
    log("  ✓ 部分遮蔽 / 完全遮蔽裁决与最小见证正确")

    # Frozen conclusions are retrievable by audit id.
    status, again = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and again["verdicts"] == body["verdicts"], (
        "按审计标识复查到的结论与提交时不一致"
    )

    # Idempotent replay of the identical payload.
    status, replay = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 200 and replay["verdicts"] == body["verdicts"], (
        f"相同载荷的幂等重放失败: HTTP {status}"
    )

    # Illegal retransmission: same audit id, different payload -> 409,
    # and the stored conclusions must stay untouched.
    tampered = json.loads(json.dumps({"audit_id": audit_id, "rules": rules}))
    tampered["rules"][1]["dst_port"]["end"] = 91
    status, conflict = http("POST", "/api/audits", tampered)
    assert status == 409, f"非法重传未被拒绝: HTTP {status} {conflict}"
    status, after = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and after["verdicts"] == body["verdicts"], (
        "非法重传改写了既有冻结结论"
    )
    log("  ✓ 非法重传被拒绝（409）且既有结论未被改写")

    # Invalid CIDR must be rejected and must not create a record.
    bad_id = audit_id + "-bad"
    bad = {"audit_id": bad_id, "rules": [dict(rules[0], src_cidr="10.0.0.0/33")]}
    status, _ = http("POST", "/api/audits", bad)
    assert status == 422, f"非法 CIDR 未被拒绝: HTTP {status}"
    status, _ = http("GET", f"/api/audits/{bad_id}")
    assert status == 404, "被拒绝的请求不应留下审计记录"
    log("  ✓ 非法 CIDR 被拒绝（422）且未留下记录")

    # The page is served.
    status, page = http("GET", "/")
    assert status == 200 and "规则隔离审计" in page, "页面不可用"
    log("  ✓ 页面与健康端点可用")


def _overlapping_ruleset(dp_end_tail: int) -> list:
    """18 legal rules whose networks and port ranges overlap heavily.

    Protocols, nested CIDRs and sliding port windows all intersect, so the
    set exercises partial overlap; the final rule is fully contained in the
    first one and therefore fully shadowed.  The only knob
    (``dp_end_tail``) moves rule r16's destination-port end to produce a
    genuinely different payload with the same audit id.
    """
    src_cidrs = [
        "10.0.0.0/16", "10.0.0.0/24", "10.1.0.0/16",
        "10.0.1.0/24", "10.2.0.0/16",
    ]
    dst_cidrs = [
        "192.168.0.0/16", "192.168.0.0/24", "192.168.1.0/24",
        "172.16.0.0/12", "192.168.2.0/24",
    ]
    rules = []
    for i in range(17):
        sp_start = (i * 1000) % 55000
        rules.append(
            {
                "id": f"r{i:02d}",
                "protocol": ["tcp", "udp", "both"][i % 3],
                "src_cidr": src_cidrs[i % len(src_cidrs)],
                "dst_cidr": dst_cidrs[i % len(dst_cidrs)],
                "src_port": {"start": sp_start, "end": min(65535, sp_start + 8000)},
                "dst_port": {
                    "start": 80 + (i % 5),
                    "end": dp_end_tail if i == 16 else 90 + (i % 7),
                },
            }
        )
    # r17: strict sub-box of r0 (tcp, 10.0.0.0/16 -> 192.168.0.0/16,
    # ports 0..8000 -> 80..90), so it is provably fully shadowed.
    rules.append(
        {
            "id": "r17",
            "protocol": "tcp",
            "src_cidr": "10.0.0.0/24",
            "dst_cidr": "192.168.0.0/24",
            "src_port": {"start": 100, "end": 200},
            "dst_port": {"start": 82, "end": 84},
        }
    )
    return rules


def concurrent_smoke() -> None:
    """Same audit id, fired simultaneously with same and different payloads."""
    assert wait_ready(), f"服务在 {APP_URL} 上未通过健康检查"

    audit_id = f"conc-{time.time_ns()}"
    payload_p = {"audit_id": audit_id, "rules": _overlapping_ruleset(120)}
    payload_q = {"audit_id": audit_id, "rules": _overlapping_ruleset(121)}
    assert json.dumps(payload_p, sort_keys=True) != json.dumps(
        payload_q, sort_keys=True
    )

    n_same, n_diff = 6, 4
    outcomes: list[tuple[str, int, object]] = []
    outcomes_lock = threading.Lock()
    start = threading.Barrier(n_same + n_diff)

    def worker(kind: str, body: dict) -> None:
        start.wait()
        status, resp = http("POST", "/api/audits", body)
        with outcomes_lock:
            outcomes.append((kind, status, resp))

    threads = [
        threading.Thread(target=worker, args=("P", payload_p)) for _ in range(n_same)
    ]
    threads += [
        threading.Thread(target=worker, args=("Q", payload_q)) for _ in range(n_diff)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert not any(t.is_alive() for t in threads), "并发请求中存在挂起"

    assert len(outcomes) == n_same + n_diff
    created = [(k, b) for k, s, b in outcomes if s == 201]
    assert len(created) == 1, f"应恰有一个 201，实际: {[s for _, s, _ in outcomes]}"
    winner_kind, winner_body = created[0]
    loser_kind = "Q" if winner_kind == "P" else "P"
    winner_payload = payload_p if winner_kind == "P" else payload_q
    loser_payload = payload_q if winner_payload is payload_p else payload_p

    # No provisional "processing" answers, no server errors.
    for kind, status, body in outcomes:
        assert status != 202, f"{kind} 收到了处理中响应: {body}"
        assert 200 <= status < 500, (kind, status, body)

    # Same-payload racers all replay the one complete frozen conclusion.
    same_responses = [b for k, s, b in outcomes if k == winner_kind]
    assert len(same_responses) == (n_same if winner_kind == "P" else n_diff)
    for body in same_responses:
        assert body == winner_body, "同载荷并发响应与创建结论不完全一致"
    assert len(winner_body["verdicts"]) == 18
    assert len({v["rule_id"] for v in winner_body["verdicts"]}) == 18
    statuses_seen = {v["status"] for v in winner_body["verdicts"]}
    assert statuses_seen == {"hit", "shadowed"}, statuses_seen
    r17 = next(v for v in winner_body["verdicts"] if v["rule_id"] == "r17")
    assert r17 == {"rule_id": "r17", "status": "shadowed", "covered_by": ["r00"]}

    # Every foreign-payload racer got a conflict response.
    diff_statuses = [s for k, s, _ in outcomes if k == loser_kind]
    assert diff_statuses and all(s == 409 for s in diff_statuses), diff_statuses
    for kind, status, body in outcomes:
        if kind == loser_kind:
            assert isinstance(body, dict) and body["detail"]["error"] == "audit_id_conflict"

    # Follow-up query by audit id returns exactly the frozen winner record.
    status, frozen = http("GET", f"/api/audits/{audit_id}")
    assert status == 200, f"冻结裁决查询失败: HTTP {status}"
    assert frozen == winner_body, "查询到的裁决与并发创建结论不一致"
    assert frozen["rules"] == winner_payload["rules"], "异载荷竞争改写了既有规则"

    # Sequential traffic afterwards: winner replays 200, loser still 409.
    status, replay = http("POST", "/api/audits", winner_payload)
    assert status == 200 and replay == winner_body
    status, conflict = http("POST", "/api/audits", loser_payload)
    assert status == 409
    status, frozen_after = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and frozen_after == winner_body, "冲突请求影响了后续查询"
    log(
        f"  ✓ 同载荷并发：1×201 + {len(same_responses) - 1}×200 完全一致；"
        f"异载荷并发：{len(diff_statuses)}×409；冻结查询一致（18 条规则）"
    )


def main() -> int:
    results: list[tuple[str, bool]] = []
    results.append(("构建检查 (compileall)", build_check()))
    results.append(("代码测试 (pytest)", code_tests()))
    for name, fn in (
        ("HTTP 冒烟（遮蔽/见证/非法重传）", smoke),
        ("HTTP 并发（同载荷重放 / 异载荷冲突）", concurrent_smoke),
    ):
        try:
            fn()
            results.append((name, True))
        except Exception as exc:  # noqa: BLE001 - report any smoke failure
            log(f"  ✗ {name}失败: {exc}")
            results.append((name, False))

    log("\n================ 验证结果 ================")
    for name, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(ok for _, ok in results)
    log(f"  总体: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
