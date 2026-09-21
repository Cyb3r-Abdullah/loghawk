"""Parser registry and format auto-detection."""

from __future__ import annotations

import os
from typing import Iterator, Sequence

from ..models import Event
from .base import BaseParser
from .linux_auth import LinuxAuthParser
from .nginx_access import NginxAccessParser
from .windows_security import WindowsSecurityParser

__all__ = [
    "BaseParser",
    "LinuxAuthParser",
    "NginxAccessParser",
    "WindowsSecurityParser",
    "available_parsers",
    "detect_parser",
    "parse_file",
    "parse_paths",
]

SNIFF_LINES = 40
MIN_CONFIDENCE = 0.25


def available_parsers(year: int | None = None) -> list[BaseParser]:
    return [LinuxAuthParser(year=year), NginxAccessParser(), WindowsSecurityParser()]


def detect_parser(path: str, year: int | None = None) -> BaseParser | None:
    """Pick the parser with the highest sniff confidence for a file."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        sample = [next(fh, "") for _ in range(SNIFF_LINES)]
    sample = [line for line in sample if line.strip()]
    if not sample:
        return None

    best: tuple[float, BaseParser] | None = None
    for parser in available_parsers(year=year):
        score = parser.sniff(sample)
        if best is None or score > best[0]:
            best = (score, parser)
    if best and best[0] >= MIN_CONFIDENCE:
        return best[1]
    return None


def parse_file(path: str, year: int | None = None, parser: BaseParser | None = None) -> list[Event]:
    """Parse one log file, auto-detecting the format unless ``parser`` is given."""
    chosen = parser or detect_parser(path, year=year)
    if chosen is None:
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return list(chosen.parse(fh))


def iter_log_files(paths: Sequence[str]) -> Iterator[str]:
    """Expand a mix of files and directories into a flat list of log files."""
    for path in paths:
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    if name.endswith((".log", ".json", ".txt")) or ".log." in name:
                        yield os.path.join(root, name)
        elif os.path.isfile(path):
            yield path


def parse_paths(paths: Sequence[str], year: int | None = None) -> tuple[list[Event], dict[str, str]]:
    """Parse every log under ``paths``. Returns (events, {path: parser_name})."""
    events: list[Event] = []
    used: dict[str, str] = {}
    for file_path in iter_log_files(paths):
        parser = detect_parser(file_path, year=year)
        if parser is None:
            used[file_path] = "unrecognized"
            continue
        parsed = parse_file(file_path, year=year, parser=parser)
        used[file_path] = f"{parser.name} ({len(parsed)} events)"
        events.extend(parsed)
    events.sort(key=lambda e: e.timestamp)
    return events, used
