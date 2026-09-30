"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, API,
                     concurrent settlement)
  3. HTTP smoke    — against the live service: one partially shadowed rule,
                     one fully shadowed rule, an illegal retransmission
                     (same audit id, different payload), invalid CIDR, and
                     concurrent waves of identical and differing payloads
                     fired under one audit id

Exits 0 only if every step passes; the Compose ``verify`` service surfaces
this as its container exit code.
"""

from __future__ import annotations

import copy
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


def wave_payload(audit_id: str, n: int = 18, twist: tuple[int, int] | None = None):
    """~18 legal rules with heavily overlapping CIDRs and port intervals."""
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
    if twist is not None:
        idx, end = twist
        rules[idx]["dst_port"] = {**rules[idx]["dst_port"], "end": end}
    return {"audit_id": audit_id, "rules": rules}


def fire_wave(payloads):
    """POST every payload concurrently behind one starting barrier."""
    results = [None] * len(payloads)
    barrier = threading.Barrier(len(payloads))

    def worker(index):
        barrier.wait()
        results[index] = http("POST", "/api/audits", payloads[index])

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(len(payloads))
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert all(result is not None for result in results), "存在并发请求未返回"
    return results


def concurrent_waves():
    # Wave 1: same audit id, identical payload — one frozen conclusion;
    # one request creates it and every loser replays the exact same body.
    same_id = f"wave-same-{int(time.time())}"
    base = wave_payload(same_id)
    results = fire_wave([copy.deepcopy(base) for _ in range(6)])
    statuses = [status for status, _ in results]
    assert 202 not in statuses, f"并发期间返回了处理中占位响应: {statuses}"
    assert sorted(statuses) == [200] * 5 + [201], statuses
    bodies = [body for _, body in results]
    assert all(body == bodies[0] for body in bodies), "并发相同载荷的响应体不一致"
    assert len(bodies[0]["verdicts"]) == 18
    status, frozen = http("GET", f"/api/audits/{same_id}")
    assert status == 200 and frozen == bodies[0], "冻结裁决与创建/重放响应不一致"
    log("  ✓ 相同载荷并发：唯一 201 + 其余 200，响应完全一致且冻结可查")

    # Wave 2: same audit id, mixed payloads fired simultaneously —
    # create / replay / conflict all in one race; the losing payloads must
    # be rejected without rewriting the frozen conclusions.
    mixed_id = f"wave-mix-{int(time.time())}"
    payload_a = wave_payload(mixed_id)
    payload_b = wave_payload(mixed_id, twist=(17, 500))
    payload_c = wave_payload(mixed_id, twist=(0, 600))
    payloads = [
        copy.deepcopy(payload_a),
        copy.deepcopy(payload_a),
        copy.deepcopy(payload_a),
        copy.deepcopy(payload_a),
        copy.deepcopy(payload_b),
        copy.deepcopy(payload_c),
    ]
    results = fire_wave(payloads)
    statuses = [status for status, _ in results]
    assert 202 not in statuses, f"并发期间返回了处理中占位响应: {statuses}"
    created = [i for i, status in enumerate(statuses) if status == 201]
    assert len(created) == 1, f"应有且仅有一个创建请求: {statuses}"
    winner_index = created[0]
    winner_payload = payloads[winner_index]
    winner_body = results[winner_index][1]

    for i, (status, body) in enumerate(results):
        if i == winner_index:
            continue
        same_as_winner = payloads[i]["rules"] == winner_payload["rules"]
        if same_as_winner:
            assert status == 200, f"相同载荷应重放: {status}"
            assert body == winner_body, "重放响应与创建响应不完全一致"
        else:
            assert status == 409, f"异载荷竞争应冲突: {status}"
            assert body["detail"]["error"] == "audit_id_conflict"
            assert "verdicts" not in body

    status, frozen = http("GET", f"/api/audits/{mixed_id}")
    assert status == 200 and frozen == winner_body, "竞争结束后冻结裁决不正确"
    assert frozen["rules"] == winner_payload["rules"]
    log("  ✓ 混合载荷并发：创建/重放/冲突各得其所，冲突未留痕、未改写、不影响查询")


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

    # Concurrent submissions of identical and differing payloads.
    concurrent_waves()

    # The page is served.
    status, page = http("GET", "/")
    assert status == 200 and "规则隔离审计" in page, "页面不可用"
    log("  ✓ 页面与健康端点可用")


def main() -> int:
    results: list[tuple[str, bool]] = []
    results.append(("构建检查 (compileall)", build_check()))
    results.append(("代码测试 (pytest)", code_tests()))
    try:
        smoke()
        results.append(("HTTP 冒烟", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ HTTP 冒烟失败: {exc}")
        results.append(("HTTP 冒烟", False))

    log("\n================ 验证结果 ================")
    for name, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(ok for _, ok in results)
    log(f"  总体: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
