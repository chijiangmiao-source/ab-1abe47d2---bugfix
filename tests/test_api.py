"""API tests: lifecycle, freezing, conflict and validation rejections."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def fresh_audit_id() -> str:
    return "t-" + uuid.uuid4().hex[:12]


def make_payload(audit_id, dp2_end=90):
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


class TestLifecycle:
    def test_create_then_get_frozen(self):
        audit_id = fresh_audit_id()
        resp = client.post("/api/audits", json=make_payload(audit_id))
        assert resp.status_code == 201
        body = resp.json()
        verdicts = {v["rule_id"]: v for v in body["verdicts"]}

        assert verdicts["r1"]["status"] == "hit"
        assert verdicts["r1"]["witness"] == {
            "protocol": "tcp",
            "src_ip": "10.0.0.0",
            "dst_ip": "192.168.0.0",
            "src_port": 0,
            "dst_port": 80,
        }
        # r2 is partially shadowed: only dst ports 86..90 remain.
        assert verdicts["r2"]["status"] == "hit"
        assert verdicts["r2"]["witness"]["dst_port"] == 86
        # r3 is fully shadowed by r1.
        assert verdicts["r3"]["status"] == "shadowed"
        assert verdicts["r3"]["covered_by"] == ["r1"]

        again = client.get(f"/api/audits/{audit_id}")
        assert again.status_code == 200
        assert again.json() == body

    def test_idempotent_replay_returns_same_conclusions(self):
        audit_id = fresh_audit_id()
        payload = make_payload(audit_id)
        first = client.post("/api/audits", json=payload)
        replay = client.post("/api/audits", json=payload)
        assert first.status_code == 201
        assert replay.status_code == 200
        assert replay.json() == first.json()

    def test_conflicting_payload_rejected_and_original_kept(self):
        audit_id = fresh_audit_id()
        original = make_payload(audit_id)
        assert client.post("/api/audits", json=original).status_code == 201

        tampered = make_payload(audit_id, dp2_end=91)
        conflict = client.post("/api/audits", json=tampered)
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error"] == "audit_id_conflict"

        frozen = client.get(f"/api/audits/{audit_id}")
        assert frozen.status_code == 200
        assert frozen.json()["rules"] == original["rules"]

    def test_unknown_audit_returns_404(self):
        resp = client.get("/api/audits/" + fresh_audit_id())
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "audit_not_found"


class TestValidation:
    def post(self, **overrides):
        payload = make_payload(fresh_audit_id())
        payload.update(overrides)
        return client.post("/api/audits", json=payload)

    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/33", "10.0.0.1/24", "300.1.1.1/8", "fe80::/10", "not-a-cidr", ""],
    )
    def test_invalid_cidr_rejected(self, cidr):
        payload = make_payload(fresh_audit_id())
        payload["rules"][0]["src_cidr"] = cidr
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "rng",
        [
            {"start": 90, "end": 80},      # start > end
            {"start": -1, "end": 80},      # below range
            {"start": 0, "end": 65536},    # above range
        ],
    )
    def test_invalid_port_range_rejected(self, rng):
        payload = make_payload(fresh_audit_id())
        payload["rules"][0]["dst_port"] = rng
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_duplicate_rule_ids_rejected(self):
        payload = make_payload(fresh_audit_id())
        payload["rules"][1]["id"] = "r1"
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_too_many_rules_rejected(self):
        payload = make_payload(fresh_audit_id())
        template = payload["rules"][0]
        payload["rules"] = [
            dict(template, id=f"r{i}") for i in range(19)
        ]
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_zero_rules_rejected(self):
        resp = self.post(rules=[])
        assert resp.status_code == 422

    @pytest.mark.parametrize("audit_id", ["", "has space", "bad/id", "-lead", "x" * 65])
    def test_invalid_audit_id_rejected(self, audit_id):
        resp = self.post(audit_id=audit_id)
        assert resp.status_code == 422

    def test_rejection_does_not_create_record(self):
        audit_id = fresh_audit_id()
        payload = make_payload(audit_id)
        payload["rules"][0]["src_cidr"] = "10.0.0.0/33"
        assert client.post("/api/audits", json=payload).status_code == 422
        assert client.get(f"/api/audits/{audit_id}").status_code == 404


class TestBasics:
    def test_healthz(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_index_page_served(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "规则隔离审计" in resp.text
