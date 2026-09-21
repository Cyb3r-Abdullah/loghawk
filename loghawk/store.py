"""SQLite persistence so alerts survive between scans and the API has a backend.

stdlib only - no ORM, no migrations to run. The alert fingerprint is the primary
key, so re-scanning the same logs updates rows instead of duplicating them, and
an analyst's triage status is preserved across scans.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Sequence

from .engine import ScanResult
from .models import Alert, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT NOT NULL,
    duration_ms  INTEGER NOT NULL,
    event_count  INTEGER NOT NULL,
    alert_count  INTEGER NOT NULL,
    risk_score   INTEGER NOT NULL,
    sources      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id            TEXT PRIMARY KEY,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL,
    severity      TEXT NOT NULL,
    score         INTEGER NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    src_ip        TEXT,
    username      TEXT,
    host          TEXT,
    event_count   INTEGER NOT NULL,
    evidence      TEXT NOT NULL,
    mitre         TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    context       TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'new',
    notes         TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_rule     ON alerts(rule_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ip       ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
"""

VALID_STATUSES = ("new", "triaging", "escalated", "resolved", "false_positive")


class AlertStore:
    """Thin persistence layer over SQLite."""

    def __init__(self, path: str = "loghawk.db") -> None:
        self.path = path
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # -- writes ----------------------------------------------------------
    def save_scan(self, result: ScanResult) -> int:
        """Persist a scan and its alerts. Returns the new scan id."""
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scans (started_at, duration_ms, event_count, alert_count,"
                " risk_score, sources) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.started_at.isoformat(),
                    result.duration_ms,
                    result.event_count,
                    len(result.alerts),
                    result.risk_score,
                    json.dumps(result.sources),
                ),
            )
            scan_id = int(cursor.lastrowid or 0)

            for alert in result.alerts:
                # ON CONFLICT keeps the analyst's status/notes on a re-scan.
                conn.execute(
                    """
                    INSERT INTO alerts (id, scan_id, rule_id, title, description,
                        severity, score, first_seen, last_seen, src_ip, username,
                        host, event_count, evidence, mitre, recommendation,
                        context, status, notes, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'new','',?)
                    ON CONFLICT(id) DO UPDATE SET
                        scan_id=excluded.scan_id,
                        score=excluded.score,
                        severity=excluded.severity,
                        last_seen=excluded.last_seen,
                        event_count=excluded.event_count,
                        updated_at=excluded.updated_at
                    """,
                    (
                        alert.fingerprint, scan_id, alert.rule_id, alert.title,
                        alert.description, alert.severity.value, alert.score,
                        alert.first_seen.isoformat(), alert.last_seen.isoformat(),
                        alert.src_ip, alert.user, alert.host, alert.event_count,
                        json.dumps(alert.evidence),
                        json.dumps([m.__dict__ for m in alert.mitre]),
                        alert.recommendation, json.dumps(alert.context, default=str),
                        now,
                    ),
                )
        return scan_id

    def set_status(self, alert_id: str, status: str, notes: str | None = None) -> bool:
        """Update an alert's triage status. Returns False if the id is unknown."""
        if status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {VALID_STATUSES}")
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            if notes is None:
                cursor = conn.execute(
                    "UPDATE alerts SET status = ?, updated_at = ? WHERE id = ?",
                    (status, now, alert_id),
                )
            else:
                cursor = conn.execute(
                    "UPDATE alerts SET status = ?, notes = ?, updated_at = ? WHERE id = ?",
                    (status, notes, now, alert_id),
                )
            return cursor.rowcount > 0

    # -- reads -----------------------------------------------------------
    def query_alerts(
        self,
        min_severity: Severity | None = None,
        rule_id: str | None = None,
        src_ip: str | None = None,
        status: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if min_severity is not None:
            allowed = [s.value for s in Severity if s.rank >= min_severity.rank]
            clauses.append(f"severity IN ({','.join('?' * len(allowed))})")
            params.extend(allowed)
        if rule_id:
            clauses.append("rule_id = ?")
            params.append(rule_id.upper())
        if src_ip:
            clauses.append("src_ip = ?")
            params.append(src_ip)
        if status:
            clauses.append("status = ?")
            params.append(status)

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY score DESC, first_seen DESC"
                " LIMIT ? OFFSET ?",
                params,
            ).fetchall()
        return [self._row_to_dict(row) for row in rows]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            severity = {
                row["severity"]: row["n"]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"
                )
            }
            by_status = {
                row["status"]: row["n"]
                for row in conn.execute(
                    "SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"
                )
            }
            # Group by rule_id alone: rules like LH-009 emit a per-signature
            # title, and the dashboard wants one bar per rule, not per variant.
            by_rule = [
                {"rule_id": row["rule_id"], "title": row["title"], "count": row["n"]}
                for row in conn.execute(
                    "SELECT rule_id, MIN(title) AS title, COUNT(*) AS n FROM alerts"
                    " GROUP BY rule_id ORDER BY n DESC, rule_id"
                )
            ]
            offenders = [
                {"ip": row["src_ip"], "alert_count": row["n"], "max_score": row["m"]}
                for row in conn.execute(
                    "SELECT src_ip, COUNT(*) AS n, MAX(score) AS m FROM alerts"
                    " WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY m DESC, n DESC LIMIT 10"
                )
            ]
            last_scan = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()
            total = conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"]

        return {
            "total_alerts": total,
            "severity_counts": {
                sev.value: severity.get(sev.value, 0) for sev in Severity
            },
            "status_counts": by_status,
            "by_rule": by_rule,
            "top_offenders": offenders,
            "last_scan": (
                {
                    "id": last_scan["id"],
                    "started_at": last_scan["started_at"],
                    "duration_ms": last_scan["duration_ms"],
                    "event_count": last_scan["event_count"],
                    "alert_count": last_scan["alert_count"],
                    "risk_score": last_scan["risk_score"],
                    "sources": json.loads(last_scan["sources"]),
                }
                if last_scan
                else None
            ),
        }

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["user"] = data.pop("username")
        for key in ("evidence", "mitre", "context"):
            try:
                data[key] = json.loads(data[key])
            except (TypeError, ValueError):
                data[key] = [] if key != "context" else {}
        return data
