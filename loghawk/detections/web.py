"""Web-layer detections over access logs: exploitation attempts and scanning."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable, Sequence

from ..enrich import geolocate, is_known_bad
from ..models import Alert, Event, EventType, MitreTechnique, Severity
from .base import BaseDetection

T1190 = MitreTechnique("T1190", "Exploit Public-Facing Application", "Initial Access")
T1595_002 = MitreTechnique("T1595.002", "Vulnerability Scanning", "Reconnaissance")
T1083 = MitreTechnique("T1083", "File and Directory Discovery", "Discovery")

# Signature name -> compiled pattern, matched against the URL-decoded request.
ATTACK_SIGNATURES: dict[str, re.Pattern[str]] = {
    "path_traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows)", re.I),
    "sql_injection": re.compile(
        r"(\bunion\b\s+\bselect\b|'\s*or\s*'?1'?\s*=\s*'?1|\bsleep\(\d|\bbenchmark\(|"
        r"information_schema|\bwaitfor\s+delay\b|;--|\bor\b\s+1\s*=\s*1)",
        re.I,
    ),
    "xss": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)", re.I),
    "command_injection": re.compile(
        r"(;\s*(cat|ls|id|whoami|wget|curl|nc)\b|\|\s*(sh|bash)\b|\$\(|`.*`)", re.I
    ),
    "log4shell": re.compile(r"\$\{jndi:(ldap|rmi|dns)", re.I),
    "sensitive_file": re.compile(
        r"(/\.env\b|/\.git/|/wp-config\.php|/\.aws/|/config\.json|/backup\.(sql|zip|tar))", re.I
    ),
    "webshell_probe": re.compile(
        r"/(shell|cmd|c99|r57|wso|adminer|phpmyadmin)[\w\-]*\.(php|asp|aspx|jsp)", re.I
    ),
}

SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|ffuf|wpscan|acunetix|nessus|"
    r"zgrab|python-requests|curl/|hydra|feroxbuster)",
    re.I,
)


class WebExploitAttempt(BaseDetection):
    rule_id = "LH-009"
    title = "Web exploitation attempt"
    description = (
        "Requests carrying payloads that match known exploitation signatures "
        "(injection, traversal, sensitive-file access)."
    )
    severity = Severity.HIGH
    base_score = 70
    max_score = 95
    mitre = (T1190, T1083)
    recommendation = (
        "Check the response codes: a 200 or 500 on a signature hit means the "
        "payload reached application logic. Review the affected endpoint's input "
        "handling and put the source behind a WAF block."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type != EventType.WEB_REQUEST or not event.src_ip:
                continue
            target = f"{event.extra.get('path_decoded', '')} {event.extra.get('user_agent', '')}"
            for sig_name, pattern in ATTACK_SIGNATURES.items():
                if pattern.search(target):
                    grouped[(event.src_ip, sig_name)].append(event)

        for (ip, sig_name), group in grouped.items():
            statuses = sorted({int(e.extra.get("status", 0)) for e in group})
            reached_app = any(s in (200, 201, 500, 502) for s in statuses)
            score = self.base_score + min(15, (len(group) - 1) * 2)
            if reached_app:
                score += 15
            if is_known_bad(ip):
                score += 8
            if sig_name in ("log4shell", "command_injection"):
                score += 10

            yield self.make_alert(
                group,
                title=f"Web exploitation attempt: {sig_name.replace('_', ' ')}",
                description=(
                    f"{len(group)} request(s) from {ip} matched the {sig_name} "
                    f"signature; response codes observed: {statuses}."
                    + (" At least one reached application logic." if reached_app else "")
                ),
                score=score,
                src_ip=ip,
                context={
                    "signature": sig_name,
                    "request_count": len(group),
                    "status_codes": statuses,
                    "reached_application": reached_app,
                    "sample_paths": sorted({str(e.extra.get("path")) for e in group})[:5],
                    "geo": geolocate(ip).to_dict(),
                    "known_bad_ip": is_known_bad(ip),
                },
            )


class WebScanning(BaseDetection):
    rule_id = "LH-010"
    title = "Automated web scanning"
    description = (
        "A source generated a burst of 4xx responses or advertised a known "
        "scanning tool in its User-Agent."
    )
    severity = Severity.MEDIUM
    base_score = 48
    max_score = 80  # scanning is internet background noise until it succeeds
    mitre = (T1595_002,)
    recommendation = (
        "Scanning alone is noise at internet scale, but pair it with any later "
        "success from the same source and it becomes the first stage of an "
        "intrusion. Rate-limit the origin and keep it on a watchlist."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        threshold = self.config.get("web_probe_threshold")
        window = self.config.get("web_window_sec")
        by_ip: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if event.event_type == EventType.WEB_REQUEST and event.src_ip:
                by_ip[event.src_ip].append(event)

        for ip, requests in by_ip.items():
            requests.sort(key=lambda e: e.timestamp)
            agents = {str(e.extra.get("user_agent", "")) for e in requests}
            scanner_agents = sorted({a for a in agents if SCANNER_AGENTS.search(a)})
            errors = [e for e in requests if 400 <= int(e.extra.get("status", 0)) < 500]

            bursts = self.sliding_window(errors, window, threshold) if len(errors) >= threshold else []
            if not bursts and not scanner_agents:
                continue

            group = bursts[0] if bursts else requests
            score = self.base_score
            if scanner_agents:
                score += 22
            if bursts:
                score += min(15, (len(group) - threshold) * 2)
            if is_known_bad(ip):
                score += 8

            parts = []
            if bursts:
                parts.append(f"{len(group)} 4xx responses in under {window // 60} minutes")
            if scanner_agents:
                parts.append(f"scanner User-Agent: {', '.join(scanner_agents[:3])}")

            yield self.make_alert(
                group,
                description=f"{ip} - " + "; ".join(parts) + ".",
                score=score,
                src_ip=ip,
                context={
                    "total_requests": len(requests),
                    "error_responses": len(errors),
                    "scanner_agents": scanner_agents,
                    "distinct_paths": len({str(e.extra.get("path")) for e in requests}),
                    "geo": geolocate(ip).to_dict(),
                    "known_bad_ip": is_known_bad(ip),
                },
            )
