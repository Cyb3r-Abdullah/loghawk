"""Privilege-escalation and persistence detections."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from ..models import Alert, Event, EventType, MitreTechnique, Severity
from .base import BaseDetection

T1548_003 = MitreTechnique("T1548.003", "Sudo and Sudo Caching", "Privilege Escalation")
T1136_001 = MitreTechnique("T1136.001", "Create Account: Local Account", "Persistence")
T1098 = MitreTechnique("T1098", "Account Manipulation", "Persistence")
T1003_008 = MitreTechnique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow",
                           "Credential Access")


class SudoAbuse(BaseDetection):
    rule_id = "LH-007"
    title = "Suspicious sudo activity"
    description = (
        "Failed sudo authentications, sudoers violations, or sudo invocations "
        "touching credential stores and other sensitive targets."
    )
    severity = Severity.HIGH
    base_score = 66
    max_score = 92
    mitre = (T1548_003, T1003_008)
    recommendation = (
        "Confirm the invoking account is authorized for the command. Repeated "
        "sudo password failures or a 'not in sudoers' entry means someone is "
        "probing for escalation - review that account's recent session history."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        sensitive = tuple(self.config.get("sensitive_commands"))
        grouped: dict[tuple[str, str | None], list[Event]] = defaultdict(list)

        for event in events:
            if event.event_type not in (
                EventType.PRIV_ESCALATION,
                EventType.PRIV_ESCALATION_FAILED,
            ):
                continue
            command = str(event.extra.get("command") or "")
            failed = event.event_type == EventType.PRIV_ESCALATION_FAILED
            touches_sensitive = any(token in command for token in sensitive)
            if failed or touches_sensitive:
                grouped[(str(event.user), event.host)].append(event)

        for (user, host), group in grouped.items():
            failures = [e for e in group if e.event_type == EventType.PRIV_ESCALATION_FAILED]
            not_in_sudoers = [e for e in group if e.extra.get("reason") == "not_in_sudoers"]
            sensitive_hits = [
                e
                for e in group
                if any(token in str(e.extra.get("command") or "") for token in sensitive)
            ]

            score = self.base_score
            if not_in_sudoers:
                score += 14
            if sensitive_hits:
                score += 12
            if len(failures) >= 3:
                score += 8
            # sudo logs "N incorrect password attempts" as one line, so the count
            # lives in the record rather than in the number of records.
            if any(int(e.extra.get("attempts") or 0) >= 3 for e in failures):
                score += 8

            reasons = []
            if failures:
                reasons.append(f"{len(failures)} failed sudo authentication(s)")
            if not_in_sudoers:
                reasons.append("account is not in sudoers")
            if sensitive_hits:
                commands = sorted({str(e.extra.get("command")) for e in sensitive_hits})
                reasons.append(f"sensitive command(s): {'; '.join(commands[:3])}")

            yield self.make_alert(
                group,
                description=f"sudo activity by '{user}' on {host or 'unknown host'}: "
                + "; ".join(reasons)
                + ".",
                score=score,
                user=user,
                host=host,
                context={
                    "failed_sudo": len(failures),
                    "not_in_sudoers": bool(not_in_sudoers),
                    "sensitive_commands": sorted(
                        {str(e.extra.get("command")) for e in sensitive_hits}
                    ),
                },
            )


class PrivilegedAccountChange(BaseDetection):
    rule_id = "LH-008"
    title = "Account created or added to a privileged group"
    description = (
        "A new account was created, or an existing account was added to an "
        "administrative group - classic post-compromise persistence."
    )
    severity = Severity.HIGH
    base_score = 74
    max_score = 95
    mitre = (T1136_001, T1098)
    recommendation = (
        "Match the change against an approved ticket. If none exists, disable the "
        "account, capture the creating session's logon ID, and pivot to the source "
        "host for the rest of the intrusion."
    )

    PRIVILEGED_GROUPS = (
        "domain admins", "enterprise admins", "administrators", "schema admins",
        "account operators", "backup operators", "sudo", "wheel", "root",
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        for event in events:
            if event.event_type == EventType.ACCOUNT_CREATED:
                yield self.make_alert(
                    [event],
                    title="New account created",
                    description=(
                        f"Account '{event.user}' was created on "
                        f"{event.host or 'unknown host'}."
                    ),
                    score=self.base_score,
                    user=event.user,
                    host=event.host,
                    src_ip=event.src_ip,
                    context={"event_id": event.extra.get("event_id")},
                )
            elif event.event_type == EventType.GROUP_MEMBER_ADDED:
                group = str(event.extra.get("target_group") or "unknown group")
                privileged = group.lower() in self.PRIVILEGED_GROUPS
                score = 88 if privileged else 50
                yield self.make_alert(
                    [event],
                    title=(
                        "Account added to privileged group"
                        if privileged
                        else "Account added to group"
                    ),
                    description=(
                        f"Account '{event.user}' was added to '{group}' on "
                        f"{event.host or 'unknown host'}."
                    ),
                    score=score,
                    user=event.user,
                    host=event.host,
                    src_ip=event.src_ip,
                    context={
                        "group": group,
                        "privileged_group": privileged,
                        "event_id": event.extra.get("event_id"),
                    },
                )
