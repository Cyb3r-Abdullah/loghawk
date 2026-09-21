"""Core data model: the normalized event and the alert produced from events.

Every parser converts its native log format into an :class:`Event`, and every
detection consumes ``Event`` objects and emits :class:`Alert` objects. Keeping
this boundary narrow is what lets a new log source be added without touching a
single detection rule.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EventType(str, Enum):
    """Vendor-neutral classification of a log line."""

    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    INVALID_USER = "invalid_user"
    SESSION_OPEN = "session_open"
    SESSION_CLOSE = "session_close"
    PRIV_ESCALATION = "priv_escalation"
    PRIV_ESCALATION_FAILED = "priv_escalation_failed"
    ACCOUNT_CREATED = "account_created"
    GROUP_MEMBER_ADDED = "group_member_added"
    SPECIAL_PRIVILEGES = "special_privileges"
    WEB_REQUEST = "web_request"
    OTHER = "other"


class Severity(str, Enum):
    """Alert severity, ordered low -> critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    @classmethod
    def from_score(cls, score: int) -> "Severity":
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class MitreTechnique:
    """A single ATT&CK technique reference attached to a detection."""

    id: str
    name: str
    tactic: str

    @property
    def url(self) -> str:
        base, _, sub = self.id.partition(".")
        if sub:
            return f"https://attack.mitre.org/techniques/{base}/{sub}/"
        return f"https://attack.mitre.org/techniques/{base}/"


@dataclass
class Event:
    """One normalized log record."""

    timestamp: datetime
    source: str
    event_type: EventType
    raw: str
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    process: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    @property
    def is_auth_attempt(self) -> bool:
        return self.event_type in (
            EventType.AUTH_SUCCESS,
            EventType.AUTH_FAILURE,
            EventType.INVALID_USER,
        )

    @property
    def is_auth_failure(self) -> bool:
        return self.event_type in (EventType.AUTH_FAILURE, EventType.INVALID_USER)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d["event_type"] = self.event_type.value
        return d


@dataclass
class Alert:
    """A detection's finding: what happened, how bad, and what to do next."""

    rule_id: str
    title: str
    description: str
    severity: Severity
    score: int
    first_seen: datetime
    last_seen: datetime
    mitre: list[MitreTechnique] = field(default_factory=list)
    src_ip: str | None = None
    user: str | None = None
    host: str | None = None
    event_count: int = 0
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""
    context: dict[str, Any] = field(default_factory=dict)

    MAX_EVIDENCE = 5

    def __post_init__(self) -> None:
        self.score = max(0, min(100, int(self.score)))
        self.evidence = self.evidence[: self.MAX_EVIDENCE]

    @property
    def fingerprint(self) -> str:
        """Stable id used to deduplicate the same finding across runs."""
        seed = "|".join(
            [
                self.rule_id,
                self.src_ip or "-",
                self.user or "-",
                self.host or "-",
                self.first_seen.isoformat(),
            ]
        )
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.fingerprint,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "score": self.score,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_seconds": self.duration_seconds,
            "mitre": [
                {"id": m.id, "name": m.name, "tactic": m.tactic, "url": m.url}
                for m in self.mitre
            ],
            "src_ip": self.src_ip,
            "user": self.user,
            "host": self.host,
            "event_count": self.event_count,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "context": self.context,
        }
