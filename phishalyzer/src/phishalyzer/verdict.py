"""Verdikt z pravidel, ne ze skóre. Pravidlo se dá vypsat na tři řádky
a obhájit — číslo 78 ne.

* malicious  — kterýkoli nález critical, nebo dva a víc high
* suspicious — jeden high, nebo tři a víc medium
* clean      — nic z toho
"""

from __future__ import annotations

from .findings import Finding, Severity

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"


def compute_verdict(findings: list[Finding]) -> str:
    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)

    if critical >= 1 or high >= 2:
        return VERDICT_MALICIOUS
    if high == 1 or medium >= 3:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN
