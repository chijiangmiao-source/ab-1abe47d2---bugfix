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

    Replaying the identical payload under the same audit id returns the
    existing frozen conclusions (200).  The same audit id with a different
    payload is rejected (409) and never rewrites the stored conclusions.
    """
    payload = req.model_dump(mode="json")
    digest = fingerprint(payload)

    existing, claimed = store.claim(req.audit_id, digest)
    if existing is not None:
        if existing.digest == digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))

    if not claimed:
        return JSONResponse(
            status_code=202,
            content={"audit_id": req.audit_id, "status": "processing"},
        )

    try:
        record = new_record(req.audit_id, payload, analyze(req.rules))
        winner = store.put_if_absent(record)
    finally:
        store.release_claim(req.audit_id, digest)

    if winner.digest != digest:
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


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
