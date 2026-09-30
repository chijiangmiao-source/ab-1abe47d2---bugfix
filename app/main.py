"""HTTP API for the flight data link rule isolation auditor."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from .engine import analyze
from .schemas import AuditRequest
from .store import AuditStore, LeaderAborted, fingerprint, new_record

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

    Concurrent submissions of the same audit id collapse into a single
    frozen conclusion: one request creates it (201) and every concurrent
    identical request blocks until the conclusions are complete and replays
    the exact same response (200).  A concurrent request carrying a
    different payload is rejected (409), stores nothing, rewrites no rule
    and does not affect later queries.  Sequential replays of the identical
    payload also return the frozen conclusions (200).
    """
    payload = req.model_dump(mode="json")
    digest = fingerprint(payload)

    # A follower retries only if its leader aborted before committing; this
    # is a defensive bound, not an expected path (validated payloads do not
    # make the engine raise).
    for _ in range(32):
        existing, slot, is_leader = store.begin(req.audit_id, digest)
        if existing is not None:
            if existing.digest == digest:
                return JSONResponse(status_code=200, content=existing.response())
            raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))

        if is_leader:
            try:
                verdicts = analyze(req.rules)
                record = new_record(req.audit_id, payload, verdicts)
                winner = store.commit(req.audit_id, slot, record)
            except BaseException:
                store.abort(req.audit_id, slot)
                raise
            status_code = 201 if winner is record else 200
            return JSONResponse(status_code=status_code, content=winner.response())

        if slot is None:
            # A concurrent leader is computing conclusions for a different
            # payload under the same audit id.
            raise HTTPException(
                status_code=409, detail=_conflict_detail(req.audit_id, inflight=True)
            )

        try:
            record = store.await_record(slot)
        except LeaderAborted:
            continue
        # begin() only hands back a slot for followers with the same digest,
        # so the published conclusions are by construction identical.
        return JSONResponse(status_code=200, content=record.response())

    raise HTTPException(status_code=503, detail="审计创建反复中止，请稍后重试。")


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


def _conflict_detail(audit_id: str, inflight: bool = False) -> dict:
    if inflight:
        message = (
            f"审计标识 {audit_id!r} 正由另一并发请求以不同载荷创建；"
            "拒绝本次提交，不留下记录，以先完成者的结论为准。"
        )
    else:
        message = (
            f"审计标识 {audit_id!r} 已存在且载荷不同；"
            "既有结论已冻结，拒绝改写。"
        )
    return {
        "error": "audit_id_conflict",
        "message": message,
        "audit_id": audit_id,
    }
