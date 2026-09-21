#!/usr/bin/env python3
"""Regenerate docs/DETECTIONS.md from the rule classes themselves.

Keeping the docs generated means the catalog can never drift from the code.

    python docs/generate_catalog.py > docs/DETECTIONS.md
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loghawk.detections import ALL_DETECTIONS  # noqa: E402


def main() -> None:
    out = sys.stdout.write

    out("# Detection catalog\n\n")
    out("Ten rules, each mapped to MITRE ATT&CK. `base_score` is the starting risk\n"
        "score; each rule adds context-dependent modifiers (threat-feed hit, privileged\n"
        "account, payload reaching application logic) and clamps the result to its own\n"
        "ceiling. Ceilings are what keep a loud *attempt* from outranking a confirmed\n"
        "*compromise* in the triage queue.\n\n")
    out("> Regenerate this file with `python docs/generate_catalog.py > docs/DETECTIONS.md`.\n\n")

    out("| Rule | Title | Base | Ceiling | ATT&CK | Tactic |\n|---|---|---|---|---|---|\n")
    for cls in ALL_DETECTIONS:
        tech = "<br>".join(f"[{m.id}]({m.url})" for m in cls.mitre)
        tactics = "<br>".join(sorted({m.tactic for m in cls.mitre}))
        out(f"| `{cls.rule_id}` | {cls.title} | {cls.base_score} | {cls.max_score} "
            f"| {tech} | {tactics} |\n")

    out("\n## Coverage by ATT&CK tactic\n\n")
    tactics: dict[str, set[str]] = {}
    for cls in ALL_DETECTIONS:
        for technique in cls.mitre:
            tactics.setdefault(technique.tactic, set()).add(cls.rule_id)
    for tactic in sorted(tactics):
        out(f"- **{tactic}** - {', '.join(sorted(tactics[tactic]))}\n")

    out("\n---\n\n")
    for cls in ALL_DETECTIONS:
        module = cls.__module__.rsplit(".", 1)[-1]
        out(f"## {cls.rule_id} - {cls.title}\n\n")
        out(f"**Default severity:** {cls.severity.value} &nbsp;&nbsp; "
            f"**Base score:** {cls.base_score} &nbsp;&nbsp; **Ceiling:** {cls.max_score}\n\n")
        out(f"{cls.description}\n\n**MITRE ATT&CK**\n\n")
        for technique in cls.mitre:
            out(f"- [{technique.id} - {technique.name}]({technique.url}) ({technique.tactic})\n")
        out(f"\n**Analyst action:** {cls.recommendation}\n\n")
        out(f"**Source:** `loghawk/detections/{module}.py` -> `{cls.__name__}`\n\n")


if __name__ == "__main__":
    main()
