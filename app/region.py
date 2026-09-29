"""Exact 5-dimensional region algebra over packet rules.

A packet is a point in a 5-dimensional space:

    (protocol, src IPv4, dst IPv4, src port, dst port)

* protocol axis: 0 = TCP, 1 = UDP ("both" is the closed interval [0, 1])
* IPv4 addresses are uint32 (0 .. 2**32 - 1)
* ports are 0 .. 65535

A rule region is an axis-aligned box: the product of 5 closed intervals.
The union of earlier rules is maintained as a list of disjoint boxes and
the remaining region of the current rule is computed by exact box
subtraction.  No address sampling, no port enumeration, no CIDR string
overlap heuristics anywhere in this module.
"""

from __future__ import annotations

import ipaddress

TCP = 0
UDP = 1
PROTOCOL_NAMES = {TCP: "tcp", UDP: "udp"}
PROTOCOL_INTERVALS = {"tcp": (TCP, TCP), "udp": (UDP, UDP), "both": (TCP, UDP)}

PORT_MIN = 0
PORT_MAX = 65535
IPV4_MIN = 0
IPV4_MAX = 0xFFFFFFFF

DIMS = 5

# A box is a tuple of DIMS inclusive (lo, hi) integer intervals:
#   ((p_lo, p_hi), (s_lo, s_hi), (d_lo, d_hi), (sp_lo, sp_hi), (dp_lo, dp_hi))


def cidr_to_interval(cidr: str) -> tuple[int, int]:
    """Convert a validated IPv4 CIDR to an inclusive uint32 interval."""
    net = ipaddress.IPv4Network(cidr, strict=True)
    return int(net.network_address), int(net.broadcast_address)


def rule_box(
    protocol: str,
    src_cidr: str,
    dst_cidr: str,
    src_port: tuple[int, int],
    dst_port: tuple[int, int],
) -> tuple:
    """Build the 5-D box for one rule."""
    return (
        PROTOCOL_INTERVALS[protocol],
        cidr_to_interval(src_cidr),
        cidr_to_interval(dst_cidr),
        (src_port[0], src_port[1]),
        (dst_port[0], dst_port[1]),
    )


def intersects(a: tuple, b: tuple) -> bool:
    """True iff boxes a and b share at least one point."""
    return all(a[d][0] <= b[d][1] and b[d][0] <= a[d][1] for d in range(DIMS))


def subtract_box(a: tuple, b: tuple) -> list[tuple]:
    """Return the disjoint boxes covering ``a \\ b`` (at most 2 * DIMS).

    Walks dimension by dimension: the slice of ``a`` below ``b`` and the
    slice above ``b`` on the current axis are emitted as pieces, while the
    overlapping middle is carried into the next dimension.  Whatever
    survives all five dimensions lies inside ``b`` and is dropped.
    """
    if not intersects(a, b):
        return [a]
    pieces: list[tuple] = []
    cur = a
    for d in range(DIMS):
        lo, hi = cur[d]
        blo, bhi = b[d]
        if lo < blo:
            piece = list(cur)
            piece[d] = (lo, blo - 1)
            pieces.append(tuple(piece))
        if bhi < hi:
            piece = list(cur)
            piece[d] = (bhi + 1, hi)
            pieces.append(tuple(piece))
        narrowed = list(cur)
        narrowed[d] = (max(lo, blo), min(hi, bhi))
        cur = tuple(narrowed)
    return pieces


def subtract_region(region: list[tuple], b: tuple) -> list[tuple]:
    """Subtract box ``b`` from every box of a disjoint box list."""
    out: list[tuple] = []
    for a in region:
        out.extend(subtract_box(a, b))
    return out


def min_point(region: list[tuple]) -> tuple[int, int, int, int, int]:
    """Lexicographically smallest packet contained in a non-empty region.

    Ordering: protocol (tcp < udp), src address, dst address, src port,
    dst port.  The minimum of a box is its low corner, so the region
    minimum is the minimum over the boxes' low corners.
    """
    return min(tuple(box[d][0] for d in range(DIMS)) for box in region)
