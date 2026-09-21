"""Parser contract shared by every log source."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Iterator

from ..models import Event


class BaseParser(ABC):
    """Turn raw log lines into normalized :class:`Event` objects.

    Subclasses implement :meth:`sniff` (cheap format check on a few sample
    lines) and :meth:`parse_line` (returns ``None`` for lines it does not care
    about, which is most of them in a real auth.log).
    """

    name: str = "base"
    description: str = ""

    @abstractmethod
    def sniff(self, sample_lines: list[str]) -> float:
        """Return confidence 0.0-1.0 that this parser handles the sample."""

    @abstractmethod
    def parse_line(self, line: str, line_no: int) -> Event | None:
        """Parse a single line, or return ``None`` to skip it."""

    def parse(self, lines: Iterable[str]) -> Iterator[Event]:
        for line_no, line in enumerate(lines, start=1):
            line = line.rstrip("\n\r")
            if not line.strip():
                continue
            try:
                event = self.parse_line(line, line_no)
            except Exception:  # noqa: BLE001 - a malformed line must never abort a scan
                continue
            if event is not None:
                yield event
