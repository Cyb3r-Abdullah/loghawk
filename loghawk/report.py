"""Output renderers: coloured console, JSON, CSV, and Markdown.

No third-party dependencies - ANSI colour is emitted directly and disabled
automatically when stdout is not a TTY (or when NO_COLOR is set), so piping to
a file produces clean text.
"""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from typing import Sequence

from .engine import ScanResult
from .models import Alert, Severity

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[97;41m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
}
SEVERITY_PLAIN = {
    Severity.CRITICAL: "\033[31m",
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[96m",
}

BANNER = r"""
  _                _   _                _
 | |    ___   __ _| | | | __ _ __      _| | __
 | |   / _ \ / _` | |_| |/ _` |\ \ /\ / / |/ /
 | |__| (_) | (_| |  _  | (_| | \ V  V /|   <
 |_____\___/ \__, |_| |_|\__,_|  \_/\_/ |_|\_\
             |___/   blue-team log detection engine
"""


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class ConsoleReporter:
    """Renders a scan result as a readable terminal report."""

    def __init__(self, color: bool | None = None, width: int = 96) -> None:
        self.color = use_color() if color is None else color
        self.width = width

    def _c(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _rule(self, char: str = "-") -> str:
        return char * self.width

    def render(self, result: ScanResult, verbose: bool = False) -> str:
        out = io.StringIO()
        w = out.write

        w(self._c(BANNER, DIM) if self.color else BANNER)
        w("\n")
        w(self._summary(result))
        w("\n")

        if not result.alerts:
            w(self._c("  No detections fired. Nothing suspicious in the supplied logs.\n", DIM))
            return out.getvalue()

        w(self._c(f"  ALERTS ({len(result.alerts)})\n", BOLD))
        w(f"  {self._rule()}\n")
        for index, alert in enumerate(result.alerts, start=1):
            w(self._alert_block(index, alert, verbose))
        w(self._offenders(result))
        if result.errors:
            w(self._c(f"\n  Rule errors: {'; '.join(result.errors)}\n", SEVERITY_PLAIN[Severity.MEDIUM]))
        return out.getvalue()

    def _summary(self, result: ScanResult) -> str:
        counts = result.severity_counts
        risk = result.risk_score
        risk_sev = Severity.from_score(risk)
        bar_len = 40
        filled = int(bar_len * risk / 100)
        bar = "#" * filled + "." * (bar_len - filled)

        lines = [
            f"  {self._c('SCAN SUMMARY', BOLD)}",
            f"  {self._rule()}",
            f"  Events parsed   : {result.event_count}",
            f"  Alerts raised   : {len(result.alerts)}",
            f"  Scan duration   : {result.duration_ms} ms",
            f"  Risk score      : {self._c(f'{risk}/100', SEVERITY_PLAIN[risk_sev])} "
            f"[{self._c(bar, SEVERITY_PLAIN[risk_sev])}] {risk_sev.value.upper()}",
            "  Severity        : "
            + "  ".join(
                self._c(f"{sev.value}={counts[sev.value]}", SEVERITY_PLAIN[sev])
                for sev in reversed(list(Severity))
            ),
        ]
        if result.sources:
            lines.append("  Sources         :")
            for path, info in result.sources.items():
                lines.append(f"      {path}  ->  {info}")
        return "\n".join(lines) + "\n"

    def _alert_block(self, index: int, alert: Alert, verbose: bool) -> str:
        badge = self._c(f" {alert.severity.value.upper():^8} ", SEVERITY_COLOR[alert.severity])
        head = (
            f"  {index:>2}. {badge} {self._c(alert.title, BOLD)} "
            f"{self._c(f'[{alert.rule_id}] score {alert.score}/100', DIM)}\n"
        )
        who = []
        if alert.src_ip:
            who.append(f"src={alert.src_ip}")
        if alert.user:
            who.append(f"user={alert.user}")
        if alert.host:
            who.append(f"host={alert.host}")
        who.append(f"events={alert.event_count}")

        body = [
            f"      {alert.description}",
            f"      {self._c(' | '.join(who), DIM)}",
            f"      {self._c('window', DIM)}  {alert.first_seen:%Y-%m-%d %H:%M:%S} -> "
            f"{alert.last_seen:%H:%M:%S} UTC",
        ]
        if alert.mitre:
            techniques = ", ".join(f"{m.id} {m.name}" for m in alert.mitre)
            body.append(f"      {self._c('ATT&CK', DIM)}  {techniques}")
        if verbose:
            if alert.evidence:
                body.append(f"      {self._c('evidence', DIM)}")
                for line in alert.evidence:
                    trimmed = line if len(line) <= self.width - 10 else line[: self.width - 13] + "..."
                    body.append(f"        {self._c(trimmed, DIM)}")
            if alert.recommendation:
                body.append(f"      {self._c('action', DIM)}  {alert.recommendation}")
        return head + "\n".join(body) + "\n\n"

    def _offenders(self, result: ScanResult) -> str:
        offenders = result.top_offenders
        if not offenders:
            return ""
        lines = [f"  {self._c('TOP SOURCES', BOLD)}", f"  {self._rule()}"]
        for entry in offenders[:5]:
            sev = Severity.from_score(entry["max_score"])
            lines.append(
                f"      {entry['ip']:<18} {entry['alert_count']:>2} alert(s)   "
                f"max score {self._c(str(entry['max_score']), SEVERITY_PLAIN[sev])}"
            )
        return "\n".join(lines) + "\n"


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, default=str)


def to_csv(alerts: Sequence[Alert]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "alert_id", "rule_id", "title", "severity", "score", "first_seen",
        "last_seen", "src_ip", "user", "host", "event_count", "mitre",
        "description", "recommendation",
    ])
    for alert in alerts:
        writer.writerow([
            alert.fingerprint, alert.rule_id, alert.title, alert.severity.value,
            alert.score, alert.first_seen.isoformat(), alert.last_seen.isoformat(),
            alert.src_ip or "", alert.user or "", alert.host or "", alert.event_count,
            " ".join(m.id for m in alert.mitre), alert.description, alert.recommendation,
        ])
    return buffer.getvalue()


def to_markdown(result: ScanResult) -> str:
    """Incident-report style Markdown, suitable for pasting into a ticket."""
    counts = result.severity_counts
    lines = [
        "# LogHawk detection report",
        "",
        f"- **Scan started:** {result.started_at:%Y-%m-%d %H:%M:%S} UTC",
        f"- **Events parsed:** {result.event_count}",
        f"- **Alerts raised:** {len(result.alerts)}",
        f"- **Overall risk score:** {result.risk_score}/100 "
        f"({Severity.from_score(result.risk_score).value.upper()})",
        f"- **Severity breakdown:** critical {counts['critical']}, high {counts['high']}, "
        f"medium {counts['medium']}, low {counts['low']}",
        "",
        "## Sources",
        "",
    ]
    for path, info in result.sources.items():
        lines.append(f"- `{path}` - {info}")
    lines += ["", "## Alert summary", "",
              "| # | Severity | Score | Rule | Title | Source | User |",
              "|---|---|---|---|---|---|---|"]
    for index, alert in enumerate(result.alerts, start=1):
        lines.append(
            f"| {index} | {alert.severity.value} | {alert.score} | {alert.rule_id} | "
            f"{alert.title} | {alert.src_ip or '-'} | {alert.user or '-'} |"
        )

    lines += ["", "## Findings", ""]
    for index, alert in enumerate(result.alerts, start=1):
        lines += [
            f"### {index}. {alert.title} ({alert.rule_id})",
            "",
            f"**Severity:** {alert.severity.value.upper()} &nbsp;&nbsp; "
            f"**Score:** {alert.score}/100 &nbsp;&nbsp; "
            f"**Events:** {alert.event_count}",
            "",
            f"**Window:** {alert.first_seen:%Y-%m-%d %H:%M:%S} - "
            f"{alert.last_seen:%Y-%m-%d %H:%M:%S} UTC",
            "",
            alert.description,
            "",
        ]
        if alert.mitre:
            techniques = ", ".join(f"[{m.id} {m.name}]({m.url})" for m in alert.mitre)
            lines += [f"**MITRE ATT&CK:** {techniques}", ""]
        if alert.evidence:
            lines += ["**Evidence**", "", "```"]
            lines += list(alert.evidence)
            lines += ["```", ""]
        if alert.recommendation:
            lines += [f"**Recommended action:** {alert.recommendation}", ""]
    return "\n".join(lines) + "\n"
