"""Tests for the priority-order shadow analysis engine."""

from __future__ import annotations

from app.engine import analyze
from app.schemas import PortRange, Rule


def make_rule(
    rid,
    protocol="tcp",
    src="10.0.0.0/24",
    dst="192.168.0.0/24",
    sp=(0, 65535),
    dp=(0, 65535),
):
    return Rule(
        id=rid,
        protocol=protocol,
        src_cidr=src,
        dst_cidr=dst,
        src_port=PortRange(start=sp[0], end=sp[1]),
        dst_port=PortRange(start=dp[0], end=dp[1]),
    )


class TestHit:
    def test_first_rule_witness_is_min_corner(self):
        (v,) = analyze([make_rule("r1", dp=(80, 90))])
        assert v["status"] == "hit"
        assert v["witness"] == {
            "protocol": "tcp",
            "src_ip": "10.0.0.0",
            "dst_ip": "192.168.0.0",
            "src_port": 0,
            "dst_port": 80,
        }

    def test_disjoint_rules_both_hit(self):
        verdicts = analyze([make_rule("r1"), make_rule("r2", protocol="udp")])
        assert [v["status"] for v in verdicts] == ["hit", "hit"]
        assert verdicts[1]["witness"]["protocol"] == "udp"

    def test_udp_rule_not_shadowed_by_tcp_rule(self):
        verdicts = analyze(
            [make_rule("r1", protocol="tcp"), make_rule("r2", protocol="udp")]
        )
        assert verdicts[1]["status"] == "hit"
        assert verdicts[1]["witness"]["protocol"] == "udp"


class TestPartialShadow:
    def test_port_tail_remains(self):
        rules = [
            make_rule("r1", dp=(80, 85)),
            make_rule("r2", src="10.0.0.128/25", dst="192.168.0.0/25", dp=(80, 90)),
        ]
        v2 = analyze(rules)[1]
        assert v2["status"] == "hit"
        assert v2["witness"] == {
            "protocol": "tcp",
            "src_ip": "10.0.0.128",
            "dst_ip": "192.168.0.0",
            "src_port": 0,
            "dst_port": 86,
        }

    def test_protocol_slice_remains(self):
        rules = [
            make_rule("r1", protocol="tcp"),
            make_rule("r2", protocol="both"),
        ]
        v2 = analyze(rules)[1]
        assert v2["status"] == "hit"
        assert v2["witness"]["protocol"] == "udp"

    def test_witness_is_lexicographic_minimum(self):
        # r1 removes the low src addresses of r2's TCP slice; the witness
        # must be the smallest remaining point, not an arbitrary one.
        rules = [
            make_rule("r1", src="10.0.0.0/25"),
            make_rule("r2", src="10.0.0.0/24"),
        ]
        v2 = analyze(rules)[1]
        assert v2["witness"]["src_ip"] == "10.0.0.128"


class TestShadowed:
    def test_fully_shadowed_by_single_rule(self):
        rules = [
            make_rule("r1"),
            make_rule("r2", src="10.0.0.0/25", dp=(80, 80)),
        ]
        v2 = analyze(rules)[1]
        assert v2 == {"rule_id": "r2", "status": "shadowed", "covered_by": ["r1"]}

    def test_identical_rule_is_shadowed(self):
        rules = [make_rule("r1"), make_rule("r2")]
        assert analyze(rules)[1]["status"] == "shadowed"

    def test_cover_by_multiple_rules(self):
        rules = [
            make_rule("r1", dp=(0, 49)),
            make_rule("r2", dp=(50, 100)),
            make_rule("r3", dp=(0, 100)),
        ]
        v3 = analyze(rules)[2]
        assert v3["status"] == "shadowed"
        assert v3["covered_by"] == ["r1", "r2"]

    def test_covered_by_lists_only_intersecting_earlier_rules(self):
        rules = [
            make_rule("r1", dp=(80, 85)),
            make_rule("r2", src="10.0.0.128/25", dp=(80, 90)),  # partial, disjoint from r3
            make_rule("r3", src="10.0.0.0/25", dp=(82, 84)),
        ]
        verdicts = analyze(rules)
        assert verdicts[1]["status"] == "hit"
        assert verdicts[2]["status"] == "shadowed"
        assert verdicts[2]["covered_by"] == ["r1"]

    def test_later_rule_does_not_shadow_earlier(self):
        rules = [
            make_rule("r1", src="10.0.0.0/25"),
            make_rule("r2", src="10.0.0.0/24"),
        ]
        verdicts = analyze(rules)
        assert verdicts[0]["status"] == "hit"
        assert verdicts[1]["status"] == "hit"
