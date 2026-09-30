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


class LeaderAborted(RuntimeError):
    """Raised to followers when the leader request fails before committing."""


class _Slot:
    """Per-audit rendezvous.

    The first request for an audit id becomes the leader and computes the
    conclusions; every concurrent follower blocks on the condition until a
    record is published, then receives that same frozen record.  A follower
    whose payload differs from the leader's gets ``None`` so the caller can
    answer 409 -- it never waits on a foreign computation and never stores
    anything.
    """

    __slots__ = ("leader_digest", "record", "aborted", "condition")

    def __init__(self, leader_digest: str, condition: threading.Condition) -> None:
        self.leader_digest = leader_digest
        self.record: AuditRecord | None = None
        self.aborted = False
        self.condition = condition


class AuditStore:
    """Thread-safe audit_id -> AuditRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, AuditRecord] = {}
        self._slots: dict[str, _Slot] = {}

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._lock:
            return self._records.get(audit_id)

    def begin(
        self, audit_id: str, digest: str
    ) -> tuple[AuditRecord | None, _Slot | None, bool]:
        """Join the creation of an audit id.

        Returns ``(record, slot, is_leader)``:

        * a finished ``record`` (slot None) -- replay it; compare digests to
          decide 200 vs 409;
        * ``(None, slot, True)`` -- this request is the leader and must
          compute and :meth:`commit` the conclusions;
        * ``(None, slot, False)`` -- a concurrent leader exists with the same
          digest; :meth:`await_record` to receive its conclusions;
        * ``(None, None, False)`` -- a concurrent leader exists with a
          different digest: the request must be rejected (409).
        """
        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                return existing, None, False
            slot = self._slots.get(audit_id)
            if slot is None:
                slot = _Slot(digest, threading.Condition(self._lock))
                self._slots[audit_id] = slot
                return None, slot, True
            if slot.leader_digest != digest:
                return None, None, False
            return None, slot, False

    def await_record(self, slot: _Slot) -> AuditRecord:
        """Block until the leader publishes the frozen record."""
        with self._lock:
            while slot.record is None:
                if slot.aborted:
                    raise LeaderAborted
                slot.condition.wait()
            return slot.record

    def commit(self, audit_id: str, slot: _Slot, record: AuditRecord) -> AuditRecord:
        """Publish the leader's conclusions; return the stored owner."""
        with self._lock:
            existing = self._records.get(audit_id)
            if existing is None:
                self._records[audit_id] = record
                existing = record
            slot.record = existing
            slot.condition.notify_all()
            if self._slots.get(audit_id) is slot:
                del self._slots[audit_id]
            return existing

    def abort(self, audit_id: str, slot: _Slot) -> None:
        """Release waiters after the leader failed; they retry as new leaders."""
        with self._lock:
            slot.aborted = True
            slot.condition.notify_all()
            if self._slots.get(audit_id) is slot:
                del self._slots[audit_id]


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
