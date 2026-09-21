"""Shared test fixtures. Pure stdlib so the suite runs under pytest or unittest."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loghawk.models import Event, EventType  # noqa: E402

BASE = datetime(2026, 9, 21, 4, 0, 0, tzinfo=timezone.utc)
SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
)


def at(seconds: int = 0, minutes: int = 0, hours: int = 0) -> datetime:
    return BASE + timedelta(hours=hours, minutes=minutes, seconds=seconds)


def event(
    event_type: EventType,
    *,
    seconds: int = 0,
    minutes: int = 0,
    hours: int = 0,
    user: str | None = None,
    ip: str | None = None,
    host: str = "web-01",
    source: str = "linux_auth",
    raw: str = "synthetic",
    **extra,
) -> Event:
    """Build a normalized event without going through a parser."""
    return Event(
        timestamp=at(seconds, minutes, hours),
        source=source,
        event_type=event_type,
        raw=raw,
        host=host,
        user=user,
        src_ip=ip,
        extra=extra,
    )


def web(path: str, *, ip: str, status: int = 200, agent: str = "Mozilla/5.0",
        seconds: int = 0, minutes: int = 0) -> Event:
    from urllib.parse import unquote_plus

    return event(
        EventType.WEB_REQUEST,
        seconds=seconds,
        minutes=minutes,
        ip=ip,
        source="nginx_access",
        raw=f'{ip} "GET {path}" {status} "{agent}"',
        method="GET",
        path=path,
        path_decoded=unquote_plus(path),
        status=status,
        user_agent=agent,
    )


def rule_ids(alerts) -> set[str]:
    return {a.rule_id for a in alerts}
