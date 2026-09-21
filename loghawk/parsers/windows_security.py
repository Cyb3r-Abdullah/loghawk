"""Parser for Windows Security log entries exported as JSON lines.

Matches the shape produced by::

    Get-WinEvent -LogName Security |
        Select-Object TimeCreated, Id, MachineName, Properties |
        ConvertTo-Json

after flattening, which is what the bundled ``samples/windows_security.json``
mimics. A JSON array in a single file is also accepted.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from ..models import Event, EventType
from .base import BaseParser

# Event ID -> (normalized type, human label)
EVENT_ID_MAP: dict[int, tuple[EventType, str]] = {
    4624: (EventType.AUTH_SUCCESS, "An account was successfully logged on"),
    4625: (EventType.AUTH_FAILURE, "An account failed to log on"),
    4634: (EventType.SESSION_CLOSE, "An account was logged off"),
    4648: (EventType.AUTH_SUCCESS, "Logon attempted using explicit credentials"),
    4672: (EventType.SPECIAL_PRIVILEGES, "Special privileges assigned to new logon"),
    4720: (EventType.ACCOUNT_CREATED, "A user account was created"),
    4728: (EventType.GROUP_MEMBER_ADDED, "Member added to a security-enabled global group"),
    4732: (EventType.GROUP_MEMBER_ADDED, "Member added to a security-enabled local group"),
    4740: (EventType.OTHER, "A user account was locked out"),
}

# Logon type 3 = network, 10 = RemoteInteractive (RDP) - the interesting ones.
LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# Kerberos/NTLM sub-status codes worth calling out in evidence.
FAILURE_REASONS = {
    "0xC0000064": "user name does not exist",
    "0xC000006A": "wrong password",
    "0xC0000072": "account disabled",
    "0xC0000234": "account locked out",
    "0xC000006F": "logon outside permitted hours",
}


def _normalize_status(value: object) -> str:
    """Normalize an NTSTATUS code to the ``0xC000006A`` spelling used in the map."""
    text = str(value or "").strip()
    if text.lower().startswith("0x"):
        return "0x" + text[2:].upper()
    return text.upper()


def _parse_ts(value: str) -> datetime:
    value = (value or "").strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    ts = datetime.fromisoformat(value)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


class WindowsSecurityParser(BaseParser):
    name = "windows_security"
    description = "Windows Security event log (JSON export)"

    def sniff(self, sample_lines: list[str]) -> float:
        if not sample_lines:
            return 0.0
        hits = 0
        for line in sample_lines:
            stripped = line.strip().lstrip("[").rstrip(",]")
            if not stripped.startswith("{"):
                continue
            try:
                obj = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(obj, dict) and ("EventID" in obj or "Id" in obj):
                hits += 1
        return hits / len(sample_lines)

    def parse_line(self, line: str, line_no: int) -> Event | None:
        stripped = line.strip().lstrip("[").rstrip(",")
        stripped = stripped[:-1] if stripped.endswith("]") else stripped
        if not stripped.startswith("{"):
            return None
        record = json.loads(stripped)
        return self.parse_record(record, line_no)

    def parse_record(self, record: dict, line_no: int) -> Event | None:
        event_id = int(record.get("EventID") or record.get("Id") or 0)
        if event_id not in EVENT_ID_MAP:
            return None
        event_type, label = EVENT_ID_MAP[event_id]

        logon_type = record.get("LogonType")
        status = _normalize_status(record.get("Status") or record.get("SubStatus"))
        ip = record.get("IpAddress") or record.get("SourceNetworkAddress")
        if ip in ("-", "::1", "127.0.0.1", ""):
            ip = None

        return Event(
            timestamp=_parse_ts(record.get("TimeCreated") or record.get("TimeGenerated")),
            source=self.name,
            event_type=event_type,
            raw=json.dumps(record, separators=(",", ":"), sort_keys=True),
            host=record.get("Computer") or record.get("MachineName"),
            user=record.get("TargetUserName") or record.get("SubjectUserName"),
            src_ip=ip,
            process="Security",
            extra={
                "event_id": event_id,
                "label": label,
                "logon_type": logon_type,
                "logon_type_name": LOGON_TYPES.get(logon_type, str(logon_type or "")),
                "status": status,
                "status_reason": FAILURE_REASONS.get(status, ""),
                "target_group": record.get("TargetGroupName") or record.get("GroupName"),
                "line_no": line_no,
            },
        )

    def parse(self, lines):  # type: ignore[override]
        """Support both JSON-lines and a single pretty-printed JSON array."""
        buffered = list(lines)
        blob = "".join(buffered).strip()
        if blob.startswith("["):
            try:
                records = json.loads(blob)
            except ValueError:
                records = None
            if isinstance(records, list):
                for idx, record in enumerate(records, start=1):
                    if not isinstance(record, dict):
                        continue
                    try:
                        event = self.parse_record(record, idx)
                    except Exception:  # noqa: BLE001
                        continue
                    if event is not None:
                        yield event
                return
        yield from super().parse(buffered)
