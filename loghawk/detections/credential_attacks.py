"""Credential-access detections: brute force, spray, enumeration, and the
successful login that follows them."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from ..enrich import geolocate, is_known_bad, is_external
from ..models import Alert, Event, EventType, MitreTechnique, Severity
from .base import BaseDetection

T1110 = MitreTechnique("T1110", "Brute Force", "Credential Access")
T1110_001 = MitreTechnique("T1110.001", "Password Guessing", "Credential Access")
T1110_003 = MitreTechnique("T1110.003", "Password Spraying", "Credential Access")
T1087 = MitreTechnique("T1087", "Account Discovery", "Discovery")
T1078 = MitreTechnique("T1078", "Valid Accounts", "Initial Access")


def _by_ip(events: Sequence[Event]) -> dict[str, list[Event]]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.src_ip:
            grouped[event.src_ip].append(event)
    return grouped


def _ip_context(ip: str) -> dict:
    geo = geolocate(ip)
    return {
        "geo": geo.to_dict(),
        "known_bad_ip": is_known_bad(ip),
        "external": is_external(ip),
    }


class SSHBruteForce(BaseDetection):
    rule_id = "LH-001"
    title = "SSH brute force"
    description = (
        "A single source address produced a high volume of failed authentications "
        "against one or more accounts in a short window."
    )
    severity = Severity.HIGH
    base_score = 68
    max_score = 90  # an attempt, however loud, ranks below a confirmed success
    mitre = (T1110, T1110_001)
    recommendation = (
        "Block the source IP at the edge firewall, confirm no session from it "
        "succeeded, and enforce key-only SSH auth with fail2ban or equivalent."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        threshold = self.config.get("brute_force_threshold")
        window = self.config.get("brute_force_window_sec")
        privileged = set(self.config.get("privileged_users"))

        for ip, ip_events in _by_ip(events).items():
            failures = [e for e in ip_events if e.is_auth_failure]
            if len(failures) < threshold:
                continue
            for burst in self.sliding_window(failures, window, threshold):
                users = sorted({e.user for e in burst if e.user})
                # A spray targets many users with few tries each; that is LH-002.
                if len(users) >= self.config.get("spray_user_threshold"):
                    continue
                score = self.base_score
                score += min(20, (len(burst) - threshold) // 5 * 4)
                if is_known_bad(ip):
                    score += 12
                if any(u.lower() in privileged for u in users):
                    score += 8
                rate = len(burst) / max(1.0, (burst[-1].timestamp - burst[0].timestamp).total_seconds())
                yield self.make_alert(
                    burst,
                    description=(
                        f"{len(burst)} failed logins from {ip} targeting "
                        f"{', '.join(users) or 'unknown users'} over "
                        f"{int((burst[-1].timestamp - burst[0].timestamp).total_seconds())}s."
                    ),
                    score=score,
                    src_ip=ip,
                    user=users[0] if len(users) == 1 else None,
                    context={
                        "failed_attempts": len(burst),
                        "targeted_users": users,
                        "attempts_per_second": round(rate, 2),
                        **_ip_context(ip),
                    },
                )


class PasswordSpray(BaseDetection):
    rule_id = "LH-002"
    title = "Password spraying"
    description = (
        "One source tried a small number of passwords against many distinct "
        "accounts - the low-and-slow pattern designed to dodge lockout policies."
    )
    severity = Severity.HIGH
    base_score = 72
    max_score = 90
    mitre = (T1110, T1110_003)
    recommendation = (
        "Review every account named in the alert for a successful logon from the "
        "same source, force a password reset on any that authenticated, and "
        "enable MFA on externally reachable authentication."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        window = self.config.get("spray_window_sec")
        user_threshold = self.config.get("spray_user_threshold")
        max_per_user = self.config.get("spray_max_attempts_per_user")

        for ip, ip_events in _by_ip(events).items():
            failures = [e for e in ip_events if e.is_auth_failure and e.user]
            if len(failures) < user_threshold:
                continue
            for burst in self.sliding_window(failures, window, user_threshold):
                per_user: dict[str, int] = defaultdict(int)
                for event in burst:
                    per_user[str(event.user)] += 1
                if len(per_user) < user_threshold:
                    continue
                if max(per_user.values()) > max_per_user:
                    continue  # too many tries per account -> brute force, not spray
                score = self.base_score + min(18, (len(per_user) - user_threshold) * 3)
                if is_known_bad(ip):
                    score += 10
                yield self.make_alert(
                    burst,
                    description=(
                        f"{ip} attempted {len(burst)} logins across {len(per_user)} "
                        f"distinct accounts with at most {max(per_user.values())} "
                        "attempt(s) each."
                    ),
                    score=score,
                    src_ip=ip,
                    context={
                        "distinct_users": len(per_user),
                        "attempts_per_user": dict(sorted(per_user.items())),
                        **_ip_context(ip),
                    },
                )


class UserEnumeration(BaseDetection):
    rule_id = "LH-003"
    title = "Account enumeration"
    description = (
        "Repeated authentication attempts against accounts that do not exist, "
        "indicating the attacker is mapping valid usernames."
    )
    severity = Severity.MEDIUM
    base_score = 45
    max_score = 70
    mitre = (T1087,)
    recommendation = (
        "Confirm SSH is not exposing user-existence differences, and treat the "
        "source as hostile reconnaissance preceding a credential attack."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        threshold = self.config.get("enumeration_user_threshold")
        for ip, ip_events in _by_ip(events).items():
            invalid = [e for e in ip_events if e.event_type == EventType.INVALID_USER and e.user]
            users = sorted({str(e.user) for e in invalid})
            if len(users) < threshold:
                continue
            score = self.base_score + min(20, (len(users) - threshold) * 2)
            if is_known_bad(ip):
                score += 10
            yield self.make_alert(
                invalid,
                description=(
                    f"{ip} probed {len(users)} non-existent accounts "
                    f"({', '.join(users[:6])}{'...' if len(users) > 6 else ''})."
                ),
                score=score,
                src_ip=ip,
                context={"invalid_users": users, **_ip_context(ip)},
            )


class SuccessAfterBruteForce(BaseDetection):
    rule_id = "LH-004"
    title = "Successful login after failed-login burst"
    description = (
        "An account authenticated successfully from a source that had just "
        "produced a burst of failures - the signature of a guessed password."
    )
    severity = Severity.CRITICAL
    base_score = 92
    mitre = (T1110, T1078)
    recommendation = (
        "Treat as a confirmed compromise until disproven: isolate the host, "
        "reset the account's credentials and any keys it holds, and hunt for "
        "post-authentication activity from the same session."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        window = self.config.get("brute_force_window_sec")
        min_failures = max(4, self.config.get("brute_force_threshold") // 2)
        privileged = set(self.config.get("privileged_users"))

        for ip, ip_events in _by_ip(events).items():
            ordered = sorted(ip_events, key=lambda e: e.timestamp)
            successes = [e for e in ordered if e.event_type == EventType.AUTH_SUCCESS]
            if not successes:
                continue
            failures = [e for e in ordered if e.is_auth_failure]
            if not failures:
                continue
            for success in successes:
                prior = [
                    f
                    for f in failures
                    if 0 <= (success.timestamp - f.timestamp).total_seconds() <= window
                ]
                if len(prior) < min_failures:
                    continue
                score = self.base_score
                if success.user and success.user.lower() in privileged:
                    score = 100
                if is_known_bad(ip):
                    score = min(100, score + 5)
                yield self.make_alert(
                    prior + [success],
                    description=(
                        f"Account '{success.user}' authenticated from {ip} after "
                        f"{len(prior)} failed attempts in the preceding "
                        f"{window // 60} minutes."
                    ),
                    score=score,
                    src_ip=ip,
                    user=success.user,
                    host=success.host,
                    context={
                        "preceding_failures": len(prior),
                        "success_at": success.timestamp.isoformat(),
                        "privileged_account": bool(
                            success.user and success.user.lower() in privileged
                        ),
                        **_ip_context(ip),
                    },
                )
