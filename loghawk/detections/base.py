"""Detection contract and shared helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..models import Alert, Event, MitreTechnique, Severity


@dataclass
class DetectionConfig:
    """Tunables every rule reads from, so thresholds live in one place."""

    brute_force_threshold: int = 8
    brute_force_window_sec: int = 300
    spray_user_threshold: int = 6
    spray_window_sec: int = 900
    spray_max_attempts_per_user: int = 3
    enumeration_user_threshold: int = 5
    impossible_travel_kmh: float = 900.0
    web_probe_threshold: int = 5
    web_window_sec: int = 300
    business_hours: tuple[int, int] = (8, 19)  # inclusive start, exclusive end, UTC
    privileged_users: tuple[str, ...] = (
        "root", "admin", "administrator", "sysadmin", "sa", "oracle", "postgres",
    )
    sensitive_commands: tuple[str, ...] = (
        "/etc/shadow", "/etc/passwd", "useradd", "usermod", "visudo", "chpasswd",
        "authorized_keys", "iptables -F", "history -c", "nc ", "ncat ", "curl ",
        "wget ", "base64 -d", "chattr",
    )
    overrides: dict[str, Any] = field(default_factory=dict)

    def get(self, key: str, default: Any = None) -> Any:
        if key in self.overrides:
            return self.overrides[key]
        return getattr(self, key, default)


class BaseDetection(ABC):
    """One detection rule.

    A rule receives the full, time-sorted event list and returns zero or more
    alerts. Rules must be side-effect free so the engine can run them in any
    order and re-run them over the same data.
    """

    rule_id: str = "GENERIC-000"
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    base_score: int = 50
    # Ceiling for this rule's score. Rules that describe an *attempt* are capped
    # below rules that describe a *confirmed* compromise, so the queue ranks the
    # way an analyst would triage it.
    max_score: int = 100
    mitre: Sequence[MitreTechnique] = ()
    recommendation: str = ""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    @abstractmethod
    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        """Analyze events and yield alerts."""

    # -- helpers shared by subclasses ------------------------------------
    def make_alert(
        self,
        events: Sequence[Event],
        *,
        title: str | None = None,
        description: str,
        score: int | None = None,
        src_ip: str | None = None,
        user: str | None = None,
        host: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> Alert:
        ordered = sorted(events, key=lambda e: e.timestamp)
        score_value = self.base_score if score is None else score
        score_value = min(score_value, self.max_score)
        return Alert(
            rule_id=self.rule_id,
            title=title or self.title,
            description=description,
            severity=Severity.from_score(score_value),
            score=score_value,
            first_seen=ordered[0].timestamp,
            last_seen=ordered[-1].timestamp,
            mitre=list(self.mitre),
            src_ip=src_ip,
            user=user,
            host=host or ordered[0].host,
            event_count=len(ordered),
            evidence=[e.raw for e in ordered[: Alert.MAX_EVIDENCE]],
            recommendation=self.recommendation,
            context=context or {},
        )

    @staticmethod
    def sliding_window(
        events: Sequence[Event], window_sec: int, threshold: int
    ) -> list[list[Event]]:
        """Return maximal bursts of >= ``threshold`` events within ``window_sec``.

        Events must already be sorted by timestamp. Each burst is returned once;
        overlapping windows are merged so a 60-attempt attack yields one alert,
        not fifty.
        """
        bursts: list[list[Event]] = []
        left = 0
        current: list[Event] | None = None
        for right, event in enumerate(events):
            while (event.timestamp - events[left].timestamp).total_seconds() > window_sec:
                left += 1
            window = events[left : right + 1]
            if len(window) >= threshold:
                if current is not None and window[0].timestamp <= current[-1].timestamp:
                    merged = {id(e): e for e in current}
                    merged.update({id(e): e for e in window})
                    current = sorted(merged.values(), key=lambda e: e.timestamp)
                    bursts[-1] = current
                else:
                    current = list(window)
                    bursts.append(current)
        return bursts
