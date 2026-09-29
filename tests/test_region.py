"""Tests for the exact 5-D region algebra.

The service itself never enumerates points; the tests may — exhaustive
enumeration over tiny grids is used here purely as an oracle to prove the
box algebra exact.
"""

from __future__ import annotations

import itertools
import random

from app.region import (
    DIMS,
    cidr_to_interval,
    intersects,
    min_point,
    rule_box,
    subtract_box,
    subtract_region,
)


def points(box):
    return set(itertools.product(*(range(lo, hi + 1) for lo, hi in box)))


def region_points(region):
    out = set()
    for box in region:
        out |= points(box)
    return out


def assert_disjoint(region):
    for i in range(len(region)):
        for j in range(i + 1, len(region)):
            assert not intersects(region[i], region[j]), (region[i], region[j])


class TestCidrToInterval:
    def test_slash32(self):
        assert cidr_to_interval("10.1.2.3/32") == (0x0A010203, 0x0A010203)

    def test_slash24(self):
        assert cidr_to_interval("10.0.1.0/24") == (0x0A000100, 0x0A0001FF)

    def test_slash8(self):
        assert cidr_to_interval("10.0.0.0/8") == (0x0A000000, 0x0AFFFFFF)

    def test_slash0(self):
        assert cidr_to_interval("0.0.0.0/0") == (0, 0xFFFFFFFF)


class TestRuleBox:
    def test_dimensions(self):
        box = rule_box("both", "10.0.0.0/24", "192.168.0.0/25", (1024, 2048), (80, 90))
        assert box == (
            (0, 1),
            (0x0A000000, 0x0A0000FF),
            (0xC0A80000, 0xC0A8007F),
            (1024, 2048),
            (80, 90),
        )

    def test_protocol_slices(self):
        assert rule_box("tcp", "0.0.0.0/0", "0.0.0.0/0", (0, 0), (0, 0))[0] == (0, 0)
        assert rule_box("udp", "0.0.0.0/0", "0.0.0.0/0", (0, 0), (0, 0))[0] == (1, 1)


class TestSubtractBox:
    def test_disjoint_returns_original(self):
        a = ((0, 1), (0, 2), (0, 2), (0, 2), (0, 1))
        b = ((0, 1), (0, 2), (0, 2), (0, 2), (2, 3))
        assert subtract_box(a, b) == [a]

    def test_contained_returns_empty(self):
        inner = ((0, 0), (1, 2), (1, 2), (1, 2), (1, 2))
        outer = ((0, 1), (0, 3), (0, 3), (0, 3), (0, 3))
        assert subtract_box(inner, outer) == []

    def test_split_single_dimension(self):
        a = ((0, 0), (0, 3), (0, 3), (0, 3), (0, 3))
        b = ((0, 0), (0, 3), (0, 3), (0, 3), (1, 2))
        assert subtract_box(a, b) == [
            ((0, 0), (0, 3), (0, 3), (0, 3), (0, 0)),
            ((0, 0), (0, 3), (0, 3), (0, 3), (3, 3)),
        ]

    def test_interior_cut_all_dimensions(self):
        a = ((0, 3), (0, 3), (0, 3), (0, 3), (0, 3))
        b = ((1, 2), (1, 2), (1, 2), (1, 2), (1, 2))
        pieces = subtract_box(a, b)
        assert len(pieces) == 2 * DIMS
        assert region_points(pieces) == points(a) - points(b)
        assert_disjoint(pieces)

    def test_random_boxes_exact(self):
        rng = random.Random(20260929)
        for _ in range(400):
            a = tuple(
                (lo := rng.randint(0, 3), rng.randint(lo, 3)) for _ in range(DIMS)
            )
            b = tuple(
                (lo := rng.randint(0, 3), rng.randint(lo, 3)) for _ in range(DIMS)
            )
            pieces = subtract_box(a, b)
            assert region_points(pieces) == points(a) - points(b)
            assert_disjoint(pieces)


class TestSubtractRegion:
    def test_sequential_subtraction_stays_exact(self):
        rng = random.Random(7)
        region = [((0, 3), (0, 3), (0, 3), (0, 3), (0, 3))]
        expected = region_points(region)
        for _ in range(6):
            b = tuple(
                (lo := rng.randint(0, 3), rng.randint(lo, 3)) for _ in range(DIMS)
            )
            region = subtract_region(region, b)
            expected -= points(b)
            assert region_points(region) == expected
            assert_disjoint(region)


class TestMinPoint:
    def test_picks_low_corner(self):
        region = [((1, 1), (5, 9), (7, 9), (0, 9), (3, 4))]
        assert min_point(region) == (1, 5, 7, 0, 3)

    def test_lexicographic_across_boxes(self):
        region = [
            ((1, 1), (0, 0), (0, 0), (0, 0), (0, 0)),  # udp, addresses 0
            ((0, 0), (9, 9), (9, 9), (9, 9), (9, 9)),  # tcp, addresses 9
        ]
        # tcp sorts before udp even though its addresses are larger.
        assert min_point(region) == (0, 9, 9, 9, 9)
