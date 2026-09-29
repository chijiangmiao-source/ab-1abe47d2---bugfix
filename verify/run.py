"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, API)
  3. HTTP smoke    — against the live service: one partially shadowed rule,
                     one fully shadowed rule, and an illegal retransmission
                     (same audit id, different payload)

Exits 0 only if every step passes; the Compose ``verify`` service surfaces
this as its container exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
