"""Parser for nginx/Apache access logs in the combined log format."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote_plus

from ..models import Event, EventType
from .base import BaseParser

# 45.83.91.22 - - [21/Sep/2026:04:20:11 +0000] "GET /x HTTP/1.1" 404 153 "-" "sqlmap/1.7"
_COMBINED = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+(?P<auth>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r"(?P<status>\d{3})\s+(?P<size>\d+|-)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def _parse_clf_time(value: str) -> datetime:
    """Parse ``21/Sep/2026:04:20:11 +0000`` without relying on the C locale."""
    datepart, _, offset = value.partition(" ")
    d, mon, rest = datepart.split("/", 2)
    year, hh, mm, ss = rest.split(":")
    ts = datetime(
        int(year), _MONTHS[mon], int(d), int(hh), int(mm), int(ss), tzinfo=timezone.utc
    )
    if offset and len(offset) == 5 and offset[0] in "+-":
        delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
        ts = ts - delta if offset[0] == "+" else ts + delta
    return ts


class NginxAccessParser(BaseParser):
    name = "nginx_access"
    description = "nginx / Apache combined access log"

    def sniff(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = sum(1 for line in sample_lines if _COMBINED.match(line.strip()))
        return hits / len(sample_lines)

    def parse_line(self, line: str, line_no: int) -> Event | None:
        m = _COMBINED.match(line.strip())
        if not m:
            return None
        path = m["path"]
        return Event(
            timestamp=_parse_clf_time(m["time"]),
            source=self.name,
            event_type=EventType.WEB_REQUEST,
            raw=line.strip(),
            host=None,
            user=None if m["auth"] in ("-", "") else m["auth"],
            src_ip=m["ip"],
            process="nginx",
            extra={
                "method": m["method"],
                "path": path,
                "path_decoded": unquote_plus(path),
                "status": int(m["status"]),
                "size": 0 if m["size"] == "-" else int(m["size"]),
                "referer": m["referer"] or "-",
                "user_agent": m["agent"] or "-",
                "line_no": line_no,
            },
        )
