"""Parser for Linux ``/var/log/auth.log`` (sshd + sudo + PAM)."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..models import Event, EventType
from .base import BaseParser

# Sep 21 04:12:33 web-01 sshd[20481]: Failed password for invalid user admin from 45.83.91.22 port 51422 ssh2
_SYSLOG = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}

_PATTERNS: list[tuple[re.Pattern[str], EventType]] = [
    (re.compile(r"^Failed password for invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     EventType.INVALID_USER),
    (re.compile(r"^Failed password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     EventType.AUTH_FAILURE),
    (re.compile(r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"),
     EventType.INVALID_USER),
    (re.compile(r"^Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     EventType.AUTH_SUCCESS),
    (re.compile(r"^Failed publickey for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"),
     EventType.AUTH_FAILURE),
    (re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<user>[\w.\-]+)"),
     EventType.SESSION_OPEN),
    (re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<user>[\w.\-]+)"),
     EventType.SESSION_CLOSE),
    (re.compile(r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?"),
     EventType.AUTH_FAILURE),
]

# sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
_SUDO_OK = re.compile(
    r"^\s*(?P<user>[\w.\-]+)\s*:\s*TTY=(?P<tty>\S*)\s*;\s*PWD=(?P<pwd>\S*)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.+)$"
)
# sudo:   deploy : 3 incorrect password attempts ; TTY=pts/0 ; ... COMMAND=/usr/bin/cat /etc/shadow
_SUDO_FAIL = re.compile(
    r"^\s*(?P<user>[\w.\-]+)\s*:\s*(?P<attempts>\d+)\s+incorrect password attempts?\s*;"
    r".*?(?:USER=(?P<target>\S+)\s*;\s*)?COMMAND=(?P<command>.+)$"
)
# sudo:   guest : user NOT in sudoers ; TTY=pts/1 ; ...
_SUDO_DENIED = re.compile(r"^\s*(?P<user>[\w.\-]+)\s*:\s*user NOT in sudoers")


class LinuxAuthParser(BaseParser):
    name = "linux_auth"
    description = "Linux auth.log / secure (sshd, sudo, PAM)"

    def __init__(self, year: int | None = None) -> None:
        # syslog omits the year, so callers pass the year the file belongs to.
        self.year = year or datetime.now(timezone.utc).year

    def sniff(self, sample_lines: list[str]) -> float:
        hits = sum(1 for line in sample_lines if _SYSLOG.match(line.strip()))
        if not sample_lines:
            return 0.0
        keyword = sum(
            1 for line in sample_lines if "sshd[" in line or "sudo:" in line or "pam_unix" in line
        )
        return min(1.0, (hits / len(sample_lines)) * 0.6 + (keyword / len(sample_lines)) * 0.4)

    def _timestamp(self, month: str, day: str, time_str: str) -> datetime:
        hh, mm, ss = (int(p) for p in time_str.split(":"))
        return datetime(
            self.year, _MONTHS[month], int(day), hh, mm, ss, tzinfo=timezone.utc
        )

    def parse_line(self, line: str, line_no: int) -> Event | None:
        match = _SYSLOG.match(line.strip())
        if not match:
            return None

        ts = self._timestamp(match["month"], match["day"], match["time"])
        host = match["host"]
        process = match["process"]
        message = match["message"]
        base = {
            "timestamp": ts,
            "source": self.name,
            "raw": line.strip(),
            "host": host,
            "process": process,
        }

        if process.startswith("sudo"):
            return self._parse_sudo(message, base, line_no)

        for pattern, event_type in _PATTERNS:
            m = pattern.match(message)
            if not m:
                continue
            groups = m.groupdict()
            return Event(
                event_type=event_type,
                user=groups.get("user"),
                src_ip=groups.get("ip"),
                extra={"port": groups.get("port"), "line_no": line_no},
                **base,
            )
        return None

    def _parse_sudo(self, message: str, base: dict, line_no: int) -> Event | None:
        m = _SUDO_FAIL.match(message)
        if m:
            return Event(
                event_type=EventType.PRIV_ESCALATION_FAILED,
                user=m["user"],
                extra={
                    "target_user": m["target"] or "root",
                    "command": m["command"],
                    "attempts": int(m["attempts"]),
                    "line_no": line_no,
                },
                **base,
            )

        m = _SUDO_DENIED.match(message)
        if m:
            return Event(
                event_type=EventType.PRIV_ESCALATION_FAILED,
                user=m["user"],
                extra={"reason": "not_in_sudoers", "line_no": line_no},
                **base,
            )

        m = _SUDO_OK.match(message)
        if m:
            return Event(
                event_type=EventType.PRIV_ESCALATION,
                user=m["user"],
                extra={
                    "target_user": m["target"],
                    "command": m["command"],
                    "tty": m["tty"],
                    "pwd": m["pwd"],
                    "line_no": line_no,
                },
                **base,
            )
        return None
