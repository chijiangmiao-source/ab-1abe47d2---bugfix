"""Unit tests for the store's concurrent settlement protocol."""

from __future__ import annotations

import threading
import time

from app.store import AuditRecord, AuditStore


def make_record(audit_id: str, digest: str, tag: int) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=digest,
        rules=[tag],
        verdicts=[tag],
        created_at="2026-09-30T00:00:00+00:00",
    )


class TestSettlement:
    def test_first_caller_claims_rest_wait(self):
        store = AuditStore()
        record, matches = store.wait_for_record("a", "d1")
        assert record is None and matches is True

        results = {}

        def waiter(digest):
            results[digest] = store.wait_for_record("a", digest)

        same = threading.Thread(target=waiter, args=("d1",))
        different = threading.Thread(target=waiter, args=("d2",))
        same.start()
        time.sleep(0.1)
        different.start()
        time.sleep(0.2)
        # Both waiters block until the claimant freezes the slot.
        assert results == {}

        winner = store.freeze(make_record("a", "d1", 1))
        same.join(2)
        different.join(2)

        same_record, same_matches = results["d1"]
        diff_record, diff_matches = results["d2"]
        assert same_record is winner and same_matches is True
        assert diff_record is winner and diff_matches is False

    def test_abandon_wakes_waiter_who_then_claims(self):
        store = AuditStore()
        record, _ = store.wait_for_record("a", "d1")
        assert record is None

        claimed = threading.Event()

        def waiter():
            claimed.result = store.wait_for_record("a", "d2")
            claimed.set()

        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.2)
        assert not claimed.is_set()

        store.abandon("a")
        assert claimed.wait(2)
        record, matches = claimed.result
        assert record is None and matches is True
        thread.join(2)

    def test_frozen_record_is_returned_without_waiting(self):
        store = AuditStore()
        frozen = make_record("a", "d1", 1)
        assert store.freeze(frozen) is frozen

        same_record, same_matches = store.wait_for_record("a", "d1")
        diff_record, diff_matches = store.wait_for_record("a", "d2")
        assert same_record is frozen and same_matches is True
        assert diff_record is frozen and diff_matches is False
