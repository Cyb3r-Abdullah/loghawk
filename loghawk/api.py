"""FastAPI service: REST API over the alert store plus the SOC dashboard.

All analysis logic lives in :mod:`loghawk.engine` and :mod:`loghawk.store`; this
module is a transport layer and nothing more, which is why the CLI and the API
can never disagree about what a detection found.

Run with::

    loghawk serve            # or: uvicorn loghawk.api:app --reload
"""

from __future__ import annotations

import os
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException, Query, UploadFile, File
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import __version__
from .detections import rule_catalog
from .engine import Engine
from .models import Severity
from .parsers import parse_paths
from .report import to_csv, to_markdown
from .store import VALID_STATUSES, AlertStore

DB_PATH = os.environ.get("LOGHAWK_DB", "loghawk.db")
DASHBOARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

app = FastAPI(
    title="LogHawk API",
    version=__version__,
    description=(
        "Blue-team log analysis and detection engine. Upload logs, run "
        "MITRE ATT&CK-mapped detections, and triage the resulting alerts."
    ),
)

_store: AlertStore | None = None


def store() -> AlertStore:
    """Lazily open the SQLite store so importing the module never touches disk."""
    global _store
    if _store is None:
        _store = AlertStore(DB_PATH)
    return _store


# --------------------------------------------------------------------------
# Schemas
# --------------------------------------------------------------------------
class StatusUpdate(BaseModel):
    status: str = Field(..., description=f"one of {list(VALID_STATUSES)}")
    notes: str | None = Field(None, description="analyst triage notes")


class ScanRequest(BaseModel):
    paths: list[str] = Field(..., description="server-side log files or directories")
    year: int | None = Field(None, description="year for syslog timestamps")
    persist: bool = Field(True, description="store the resulting alerts")


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    rules_loaded: int
    time: str


# --------------------------------------------------------------------------
# Meta
# --------------------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse, tags=["meta"])
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=__version__,
        database=DB_PATH,
        rules_loaded=len(rule_catalog()),
        time=datetime.now(timezone.utc).isoformat(),
    )


@app.get("/api/rules", tags=["meta"])
def rules() -> list[dict[str, Any]]:
    """The detection catalog, including each rule's ATT&CK mapping."""
    return rule_catalog()


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------
@app.get("/api/alerts", tags=["alerts"])
def list_alerts(
    min_severity: str | None = Query(None, pattern="^(low|medium|high|critical)$"),
    rule_id: str | None = None,
    src_ip: str | None = None,
    status: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    alerts = store().query_alerts(
        min_severity=Severity(min_severity) if min_severity else None,
        rule_id=rule_id,
        src_ip=src_ip,
        status=status,
        limit=limit,
        offset=offset,
    )
    return {"count": len(alerts), "limit": limit, "offset": offset, "alerts": alerts}


@app.get("/api/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: str) -> dict[str, Any]:
    alert = store().get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    return alert


@app.patch("/api/alerts/{alert_id}", tags=["alerts"])
def update_alert(alert_id: str, update: StatusUpdate) -> dict[str, Any]:
    """Move an alert through triage: new -> triaging -> escalated/resolved."""
    if update.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422, detail=f"status must be one of {list(VALID_STATUSES)}"
        )
    if not store().set_status(alert_id, update.status, update.notes):
        raise HTTPException(status_code=404, detail=f"No alert with id {alert_id}")
    return store().get_alert(alert_id) or {}


@app.get("/api/stats", tags=["alerts"])
def stats() -> dict[str, Any]:
    """Counts by severity, status and rule, plus the top source addresses."""
    return store().stats()


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
@app.post("/api/scan", tags=["scan"])
def scan(request: ScanRequest) -> dict[str, Any]:
    """Scan log files that already exist on the server's filesystem."""
    for path in request.paths:
        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail=f"Path not found: {path}")

    events, sources = parse_paths(request.paths, year=request.year)
    if not events:
        raise HTTPException(status_code=422, detail="No parsable log events found")

    result = Engine().analyze(events, sources)
    payload = result.to_dict()
    if request.persist:
        payload["scan_id"] = store().save_scan(result)
    return payload


@app.post("/api/scan/upload", tags=["scan"])
async def scan_upload(
    files: list[UploadFile] = File(..., description="log files to analyze"),
    year: int | None = None,
    persist: bool = True,
) -> dict[str, Any]:
    """Upload one or more log files and analyze them in a temporary directory."""
    tmpdir = tempfile.mkdtemp(prefix="loghawk-")
    try:
        total = 0
        for upload in files:
            name = os.path.basename(upload.filename or "upload.log")
            if not name:
                continue
            target = os.path.join(tmpdir, name)
            with open(target, "wb") as fh:
                while chunk := await upload.read(1024 * 1024):
                    total += len(chunk)
                    if total > MAX_UPLOAD_BYTES:
                        raise HTTPException(
                            status_code=413,
                            detail=f"Upload exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
                        )
                    fh.write(chunk)

        events, sources = parse_paths([tmpdir], year=year)
        if not events:
            raise HTTPException(status_code=422, detail="No parsable log events found")

        result = Engine().analyze(events, sources)
        payload = result.to_dict()
        if persist:
            payload["scan_id"] = store().save_scan(result)
        return payload
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------
@app.get("/api/export/{fmt}", tags=["export"], response_class=PlainTextResponse)
def export(fmt: str, min_severity: str | None = None) -> PlainTextResponse:
    """Export stored alerts as CSV or a Markdown incident report."""
    if fmt not in ("csv", "markdown"):
        raise HTTPException(status_code=400, detail="fmt must be 'csv' or 'markdown'")

    from .engine import ScanResult
    from .models import Alert, MitreTechnique

    rows = store().query_alerts(
        min_severity=Severity(min_severity) if min_severity else None, limit=1000
    )
    alerts = [
        Alert(
            rule_id=row["rule_id"],
            title=row["title"],
            description=row["description"],
            severity=Severity(row["severity"]),
            score=row["score"],
            first_seen=datetime.fromisoformat(row["first_seen"]),
            last_seen=datetime.fromisoformat(row["last_seen"]),
            mitre=[MitreTechnique(**m) for m in row["mitre"]],
            src_ip=row["src_ip"],
            user=row["user"],
            host=row["host"],
            event_count=row["event_count"],
            evidence=row["evidence"],
            recommendation=row["recommendation"],
            context=row["context"],
        )
        for row in rows
    ]

    if fmt == "csv":
        return PlainTextResponse(
            to_csv(alerts),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=loghawk-alerts.csv"},
        )

    summary = store().stats()
    last = summary.get("last_scan") or {}
    result = ScanResult(
        alerts=alerts,
        event_count=last.get("event_count", 0),
        sources=last.get("sources", {}),
    )
    return PlainTextResponse(
        to_markdown(result),
        media_type="text/markdown",
        headers={"Content-Disposition": "attachment; filename=loghawk-report.md"},
    )


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def dashboard() -> HTMLResponse:
    try:
        with open(DASHBOARD, "r", encoding="utf-8") as fh:
            return HTMLResponse(fh.read())
    except OSError:
        raise HTTPException(status_code=500, detail="dashboard.html is missing")
