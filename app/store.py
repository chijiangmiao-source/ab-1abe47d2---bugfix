"""In-memory store of frozen audit conclusions."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone


def fingerprint(payload: dict) -> str:
    """Stable digest of a canonicalized request payload."""
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """Immutable per-audit conclusion set."""

    audit_id: str
    digest: str
    rules: list
    verdicts: list
    created_at: str

    def response(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "rules": self.rules,
            "verdicts": self.verdicts,
        }


class AuditStore:
    """Thread-safe audit_id -> AuditRecord map.  Records never change.

    For each audit id at most one request computes the conclusions at a
    time.  Concurrent requests for the same id wait for that computation to
    finish and then receive the frozen record (identical payload) or a
    conflict (different payload); a request never observes an in-progress
    placeholder.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._records: dict[str, AuditRecord] = {}
        # Ids whose conclusions are currently being computed.
        self._inflight: set[str] = set()

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._cond:
            return self._records.get(audit_id)

    def wait_for_record(self, audit_id: str, digest: str) -> tuple[AuditRecord, bool]:
        """Settle a submission once no other request is computing it.

        Blocks while another request holds the in-flight slot for
        ``audit_id``, then resolves against the frozen record:

        * the slot was frozen by an identical payload  -> ``(record, True)``
        * the slot was frozen by a different payload   -> ``(record, False)``
        * the slot is free (the previous claimant
          abandoned it, or nobody ever claimed it)     -> ``(None, True)``;
          the caller now owns the in-flight slot and MUST finish the
          settlement with either :meth:`freeze` or :meth:`abandon`.
        """
        with self._cond:
            while audit_id in self._inflight:
                self._cond.wait()
            record = self._records.get(audit_id)
            if record is not None:
                return record, record.digest == digest
            self._inflight.add(audit_id)
            return None, True

    def freeze(self, record: AuditRecord) -> AuditRecord:
        """Publish the claimant's conclusions and wake every waiter.

        Returns the record that owns the slot: the given record on first
        publication, or the pre-existing record if the slot was already
        frozen while the claimant worked.
        """
        with self._cond:
            existing = self._records.get(record.audit_id)
            if existing is None:
                self._records[record.audit_id] = record
                existing = record
            self._inflight.discard(record.audit_id)
            self._cond.notify_all()
            return existing

    def abandon(self, audit_id: str) -> None:
        """Release the in-flight slot after a claimant failed to finish.

        No record is published; waiters wake and may claim the slot
        themselves.
        """
        with self._cond:
            self._inflight.discard(audit_id)
            self._cond.notify_all()


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
