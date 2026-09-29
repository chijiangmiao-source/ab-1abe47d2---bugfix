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
    """Thread-safe audit_id -> AuditRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuditRecord] = {}
        self._claims: dict[str, str] = {}

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._lock:
            return self._records.get(audit_id)

    def put_if_absent(self, record: AuditRecord) -> AuditRecord:
        """Store the record; return whatever record owns the slot."""
        with self._lock:
            existing = self._records.get(record.audit_id)
            if existing is not None:
                return existing
            self._records[record.audit_id] = record
            return record

    def claim(self, audit_id: str, digest: str) -> tuple[AuditRecord | None, bool]:
        with self._lock:
            existing = self._records.get(audit_id)
            if existing is not None:
                return existing, False
            if audit_id in self._claims:
                return None, False
            self._claims[audit_id] = digest
            return None, True

    def release_claim(self, audit_id: str, digest: str) -> None:
        with self._lock:
            if self._claims.get(audit_id) == digest:
                del self._claims[audit_id]


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
