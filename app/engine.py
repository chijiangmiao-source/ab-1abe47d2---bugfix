"""Shadow analysis: replay rules in priority order over exact 5-D regions."""

from __future__ import annotations

import ipaddress

from .region import (
    PROTOCOL_NAMES,
    intersects,
    min_point,
    rule_box,
    subtract_region,
)


def _witness(point: tuple[int, int, int, int, int]) -> dict:
    proto, src, dst, sport, dport = point
    return {
        "protocol": PROTOCOL_NAMES[proto],
        "src_ip": str(ipaddress.IPv4Address(src)),
        "dst_ip": str(ipaddress.IPv4Address(dst)),
        "src_port": sport,
        "dst_port": dport,
    }


def _box_of(rule) -> tuple:
    return rule_box(
        rule.protocol,
        rule.src_cidr,
        rule.dst_cidr,
        (rule.src_port.start, rule.src_port.end),
        (rule.dst_port.start, rule.dst_port.end),
    )


def analyze(rules) -> list[dict]:
    """Return one verdict per rule, in submission (priority) order.

    For each rule the exact remaining region (rule minus the union of all
    earlier rules) is computed.  A rule with a non-empty remainder is
    ``hit`` and reports the minimal packet witness; a rule with an empty
    remainder is ``shadowed`` and reports every earlier rule whose region
    intersects it — the union of those rules provably covers it.
    """
    prior: list[tuple[str, tuple]] = []  # exact union of earlier rules
    verdicts: list[dict] = []
    for rule in rules:
        box = _box_of(rule)
        remainder = [box]
        for _rule_id, prior_box in prior:
            if not remainder:
                break
            remainder = subtract_region(remainder, prior_box)
        if remainder:
            verdicts.append(
                {
                    "rule_id": rule.id,
                    "status": "hit",
                    "witness": _witness(min_point(remainder)),
                }
            )
        else:
            covered_by = [rid for rid, pbox in prior if intersects(box, pbox)]
            verdicts.append(
                {
                    "rule_id": rule.id,
                    "status": "shadowed",
                    "covered_by": covered_by,
                }
            )
        prior.append((rule.id, box))
    return verdicts
