"""Detection registry.

Adding a rule means: write the class, import it here, add it to ``ALL_DETECTIONS``.
Nothing else in the codebase needs to change.
"""

from __future__ import annotations

from .base import BaseDetection, DetectionConfig
from .credential_attacks import (
    PasswordSpray,
    SSHBruteForce,
    SuccessAfterBruteForce,
    UserEnumeration,
)
from .identity import ImpossibleTravel, OffHoursPrivilegedAccess
from .privilege import PrivilegedAccountChange, SudoAbuse
from .web import WebExploitAttempt, WebScanning

ALL_DETECTIONS: list[type[BaseDetection]] = [
    SSHBruteForce,
    PasswordSpray,
    UserEnumeration,
    SuccessAfterBruteForce,
    ImpossibleTravel,
    OffHoursPrivilegedAccess,
    SudoAbuse,
    PrivilegedAccountChange,
    WebExploitAttempt,
    WebScanning,
]

__all__ = [
    "ALL_DETECTIONS",
    "BaseDetection",
    "DetectionConfig",
    "build_detections",
    "rule_catalog",
]


def build_detections(
    config: DetectionConfig | None = None,
    enabled: list[str] | None = None,
    disabled: list[str] | None = None,
) -> list[BaseDetection]:
    """Instantiate the rule set, honouring include/exclude lists of rule IDs."""
    config = config or DetectionConfig()
    enabled_set = {r.upper() for r in enabled} if enabled else None
    disabled_set = {r.upper() for r in disabled} if disabled else set()

    rules: list[BaseDetection] = []
    for cls in ALL_DETECTIONS:
        if enabled_set is not None and cls.rule_id.upper() not in enabled_set:
            continue
        if cls.rule_id.upper() in disabled_set:
            continue
        rules.append(cls(config))
    return rules


def rule_catalog() -> list[dict]:
    """Machine-readable description of every rule, for docs and the API."""
    return [
        {
            "rule_id": cls.rule_id,
            "title": cls.title,
            "description": cls.description,
            "default_severity": cls.severity.value,
            "base_score": cls.base_score,
            "mitre": [
                {"id": m.id, "name": m.name, "tactic": m.tactic, "url": m.url}
                for m in cls.mitre
            ],
            "recommendation": cls.recommendation,
        }
        for cls in ALL_DETECTIONS
    ]
