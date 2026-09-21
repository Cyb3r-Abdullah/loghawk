"""IP enrichment: private-range classification and coarse geolocation.

The bundled geo table is a deliberately small demo dataset so the project runs
offline with zero API keys. :func:`geolocate` is the only function that knows
about it, so swapping in MaxMind GeoLite2 (or ip-api, ipinfo, ...) means
replacing one function body and nothing else.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

_GEO_DB_PATH = os.path.join(os.path.dirname(__file__), "data", "geo_ranges.json")

# Netblocks seen repeatedly in credential-stuffing and scanning campaigns.
# In production this list is fed by a threat-intel feed; here it is static so
# the demo is reproducible.
THREAT_FEED_CIDRS = [
    "45.83.91.0/24",
    "185.220.101.0/24",
    "103.149.162.0/24",
]


@dataclass
class GeoInfo:
    ip: str
    is_private: bool
    country: str
    city: str
    latitude: float | None
    longitude: float | None

    @property
    def known_location(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "is_private": self.is_private,
            "country": self.country,
            "city": self.city,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }


@lru_cache(maxsize=1)
def _geo_table() -> list[tuple[ipaddress.IPv4Network, dict[str, Any]]]:
    try:
        with open(_GEO_DB_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return []
    table: list[tuple[ipaddress.IPv4Network, dict[str, Any]]] = []
    for entry in raw:
        try:
            net = ipaddress.ip_network(entry["cidr"], strict=False)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network):
            table.append((net, entry))
    # Longest prefix first so the most specific block wins.
    table.sort(key=lambda item: item[0].prefixlen, reverse=True)
    return table


@lru_cache(maxsize=4096)
def geolocate(ip: str) -> GeoInfo:
    """Resolve an IP to a coarse location. Never raises; unknown is a valid answer."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return GeoInfo(ip, False, "unknown", "unknown", None, None)

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return GeoInfo(ip, True, "internal", "internal network", None, None)

    for net, entry in _geo_table():
        if addr.version == 4 and addr in net:
            return GeoInfo(
                ip,
                False,
                entry.get("country", "unknown"),
                entry.get("city", "unknown"),
                entry.get("lat"),
                entry.get("lon"),
            )
    return GeoInfo(ip, False, "unknown", "unknown", None, None)


@lru_cache(maxsize=4096)
def is_known_bad(ip: str) -> bool:
    """True if the IP falls inside a netblock from the bundled threat feed."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in THREAT_FEED_CIDRS:
        if addr in ipaddress.ip_network(cidr, strict=False):
            return True
    return False


def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    radius = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(a))
