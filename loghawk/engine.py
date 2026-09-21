"""The analysis engine: events in, deduplicated and ranked alerts out."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from .detections import BaseDetection, DetectionConfig, build_detections
from .models import Alert, Event, Severity


@dataclass
class ScanResult:
    """Everything a single scan produced, ready to render or persist."""

    alerts: list[Alert] = field(default_factory=list)
    event_count: int = 0
    sources: dict[str, str] = field(default_factory=dict)
    duration_ms: int = 0
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    errors: list[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = Counter(alert.severity.value for alert in self.alerts)
        return {sev.value: counts.get(sev.value, 0) for sev in Severity}

    @property
    def risk_score(self) -> int:
        """Overall posture score 0-100, dominated by the worst finding.

        Deliberately not an average: ten low alerts must never outrank one
        confirmed compromise.
        """
        if not self.alerts:
            return 0
        top = max(alert.score for alert in self.alerts)
        breadth = min(15, len(self.alerts))
        return min(100, top + breadth // 3)

    @property
    def top_offenders(self) -> list[dict[str, Any]]:
        counter: Counter[str] = Counter()
        scores: dict[str, int] = {}
        for alert in self.alerts:
            if not alert.src_ip:
                continue
            counter[alert.src_ip] += 1
            scores[alert.src_ip] = max(scores.get(alert.src_ip, 0), alert.score)
        return [
            {"ip": ip, "alert_count": count, "max_score": scores[ip]}
            for ip, count in counter.most_common(10)
        ]

    def filter(
        self, min_severity: Severity | None = None, rule_id: str | None = None
    ) -> list[Alert]:
        alerts = self.alerts
        if min_severity is not None:
            alerts = [a for a in alerts if a.severity.rank >= min_severity.rank]
        if rule_id:
            alerts = [a for a in alerts if a.rule_id.upper() == rule_id.upper()]
        return alerts

    def to_dict(self) -> dict[str, Any]:
        return {
            "started_at": self.started_at.isoformat(),
            "duration_ms": self.duration_ms,
            "event_count": self.event_count,
            "alert_count": len(self.alerts),
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts,
            "sources": self.sources,
            "top_offenders": self.top_offenders,
            "errors": self.errors,
            "alerts": [alert.to_dict() for alert in self.alerts],
        }



class Engine:
    """Runs a set of detections over a set of events."""

    def __init__(
        self,
        config: DetectionConfig | None = None,
        detections: Sequence[BaseDetection] | None = None,
    ) -> None:
        self.config = config or DetectionConfig()
        self.detections = list(detections) if detections is not None else build_detections(self.config)

    def analyze(
        self, events: Sequence[Event], sources: dict[str, str] | None = None
    ) -> ScanResult:
        started = time.perf_counter()
        ordered = sorted(events, key=lambda e: e.timestamp)
        result = ScanResult(event_count=len(ordered), sources=sources or {})

        for detection in self.detections:
            try:
                result.alerts.extend(detection.run(ordered))
            except Exception as exc:  # noqa: BLE001 - one bad rule must not kill the scan
                result.errors.append(f"{detection.rule_id}: {type(exc).__name__}: {exc}")

        result.alerts = self._dedupe(result.alerts)
        result.alerts.sort(key=lambda a: (-a.score, a.first_seen))
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        return result

    @staticmethod
    def _dedupe(alerts: list[Alert]) -> list[Alert]:
        """Collapse alerts sharing a fingerprint, keeping the highest-scoring one."""
        best: dict[str, Alert] = {}
        for alert in alerts:
            existing = best.get(alert.fingerprint)
            if existing is None or alert.score > existing.score:
                best[alert.fingerprint] = alert
        return list(best.values())
