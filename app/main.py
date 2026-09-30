"""HTTP API for the flight data link rule isolation auditor."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from .engine import analyze
from .schemas import AuditRequest
from .store import AuditStore, fingerprint, new_record

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="飞行数据链路规则隔离审计", version="1.0.0")
store = AuditStore()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    errors = [
        {
            "loc": [str(part) for part in err.get("loc", [])],
            "msg": str(err.get("msg", "")),
            "type": str(err.get("type", "")),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "请求未通过校验", "errors": errors},
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/audits", status_code=201)
def create_audit(req: AuditRequest):
    """Freeze per-rule verdicts for a new audit identifier.

    Concurrent submissions of the identical payload under the same audit
    id settle as one frozen conclusion: one request creates it (201) and
    every other request waits for the computation to finish and replays
    the byte-identical conclusions (200).  Concurrent submissions of a
    different payload under the same id are rejected (409) only once the
    winning conclusion is frozen; the rejected request never stores a
    record, never rewrites the winner and never affects later lookups.
    """
    payload = req.model_dump(mode="json")
    digest = fingerprint(payload)
    audit_id = req.audit_id

    record, matches = store.wait_for_record(audit_id, digest)
    if record is not None:
        if matches:
            return JSONResponse(status_code=200, content=record.response())
        raise HTTPException(status_code=409, detail=_conflict_detail(audit_id))

    # This request owns the in-flight slot: compute the conclusions once.
    try:
        record = new_record(audit_id, payload, analyze(req.rules))
        winner = store.freeze(record)
    except BaseException:
        # Let waiters claim the slot and retry instead of blocking forever.
        store.abandon(audit_id)
        raise

    if winner is not record:
        # Defensive: only the slot holder can freeze it, so this should be
        # unreachable; never silently serve another payload's conclusions.
        if winner.digest == digest:
            return JSONResponse(status_code=200, content=winner.response())
        raise HTTPException(status_code=409, detail=_conflict_detail(audit_id))
    return JSONResponse(status_code=201, content=winner.response())


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """Return the frozen conclusions for an audit identifier."""
    record = store.get(audit_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_not_found",
                "message": f"审计标识 {audit_id!r} 不存在。",
                "audit_id": audit_id,
            },
        )
    return record.response()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _conflict_detail(audit_id: str) -> dict:
    return {
        "error": "audit_id_conflict",
        "message": (
            f"审计标识 {audit_id!r} 已存在且载荷不同；"
            "既有结论已冻结，拒绝改写。"
        ),
        "audit_id": audit_id,
    }
