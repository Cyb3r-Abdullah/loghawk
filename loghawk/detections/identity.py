"""Identity-centric detections that reason about where and when a user logs in."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Sequence

from ..enrich import geolocate, haversine_km, is_external
from ..models import Alert, Event, EventType, MitreTechnique, Severity
from .base import BaseDetection

T1078 = MitreTechnique("T1078", "Valid Accounts", "Defense Evasion")
T1078_003 = MitreTechnique("T1078.003", "Local Accounts", "Persistence")


class ImpossibleTravel(BaseDetection):
    rule_id = "LH-005"
    title = "Impossible travel"
    description = (
        "The same account authenticated from two geographic locations too far "
        "apart to be reached in the elapsed time, implying shared or stolen "
        "credentials."
    )
    severity = Severity.HIGH
    base_score = 78
    max_score = 90  # geo data is coarse; never let this outrank a proven compromise
    mitre = (T1078,)
    recommendation = (
        "Verify with the account owner whether both sessions are theirs. If not, "
        "revoke active sessions, reset credentials and check for VPN or proxy use "
        "that could explain the geography before escalating."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        max_kmh = float(self.config.get("impossible_travel_kmh"))
        by_user: dict[str, list[Event]] = defaultdict(list)
        for event in events:
            if (
                event.event_type == EventType.AUTH_SUCCESS
                and event.user
                and event.src_ip
                and is_external(event.src_ip)
            ):
                by_user[event.user].append(event)

        for user, logins in by_user.items():
            logins.sort(key=lambda e: e.timestamp)
            for prev, curr in zip(logins, logins[1:]):
                geo_a = geolocate(str(prev.src_ip))
                geo_b = geolocate(str(curr.src_ip))
                if not (geo_a.known_location and geo_b.known_location):
                    continue
                if geo_a.country == geo_b.country:
                    continue
                distance = haversine_km(
                    float(geo_a.latitude), float(geo_a.longitude),
                    float(geo_b.latitude), float(geo_b.longitude),
                )
                hours = (curr.timestamp - prev.timestamp).total_seconds() / 3600.0
                if hours <= 0:
                    hours = 1.0 / 3600.0
                speed = distance / hours
                if speed <= max_kmh or distance < 400:
                    continue
                score = self.base_score + min(20, int(speed / max_kmh) * 5)
                yield self.make_alert(
                    [prev, curr],
                    description=(
                        f"'{user}' logged in from {geo_a.city} ({geo_a.country}) and "
                        f"{geo_b.city} ({geo_b.country}) {hours * 60:.0f} minutes apart "
                        f"- {distance:.0f} km, implying {speed:.0f} km/h."
                    ),
                    score=score,
                    user=user,
                    src_ip=curr.src_ip,
                    host=curr.host,
                    context={
                        "from": geo_a.to_dict(),
                        "to": geo_b.to_dict(),
                        "distance_km": round(distance, 1),
                        "elapsed_minutes": round(hours * 60, 1),
                        "implied_kmh": round(speed),
                    },
                )


class OffHoursPrivilegedAccess(BaseDetection):
    rule_id = "LH-006"
    title = "Off-hours privileged logon"
    description = (
        "A privileged account authenticated outside configured business hours, "
        "when legitimate administrative work is unlikely."
    )
    severity = Severity.MEDIUM
    base_score = 52
    max_score = 75  # a hunting lead, not an incident on its own
    mitre = (T1078_003,)
    recommendation = (
        "Correlate with the change calendar and on-call roster. Unscheduled "
        "out-of-hours root access is a high-value hunting lead even when benign."
    )

    def run(self, events: Sequence[Event]) -> Iterable[Alert]:
        start, end = self.config.get("business_hours")
        privileged = set(self.config.get("privileged_users"))
        grouped: dict[tuple[str, str | None], list[Event]] = defaultdict(list)

        for event in events:
            if event.event_type != EventType.AUTH_SUCCESS or not event.user:
                continue
            if event.user.lower() not in privileged:
                continue
            hour = event.timestamp.hour
            if start <= hour < end:
                continue
            grouped[(event.user, event.src_ip)].append(event)

        for (user, ip), group in grouped.items():
            score = self.base_score
            if ip and is_external(ip):
                score += 15
            geo = geolocate(ip) if ip else None
            yield self.make_alert(
                group,
                description=(
                    f"Privileged account '{user}' authenticated {len(group)} time(s) "
                    f"outside {start:02d}:00-{end:02d}:00 UTC"
                    + (f" from {ip}" if ip else "")
                    + "."
                ),
                score=score,
                user=user,
                src_ip=ip,
                context={
                    "business_hours_utc": f"{start:02d}:00-{end:02d}:00",
                    "logon_hours_utc": sorted({e.timestamp.hour for e in group}),
                    "geo": geo.to_dict() if geo else None,
                    "external": bool(ip and is_external(ip)),
                },
            )
