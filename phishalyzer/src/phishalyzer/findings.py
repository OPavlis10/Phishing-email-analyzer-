"""Datové třídy nálezů. Nález je struktura, ne řetězec."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pro JSON i textový výstup
        return self.name.lower()


@dataclass(frozen=True)
class Finding:
    """Jeden nález s důkazy, které si uživatel může ověřit sám."""

    id: str
    severity: Severity
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": str(self.severity),
            "title": self.title,
            "evidence": self.evidence,
            "explanation": self.explanation,
        }
