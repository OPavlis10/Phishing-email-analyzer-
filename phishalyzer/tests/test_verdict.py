from phishalyzer.findings import Finding, Severity
from phishalyzer.verdict import compute_verdict


def make(severity, n):
    return [Finding(id=f"f{i}", severity=severity, title="t") for i in range(n)]


def test_clean():
    assert compute_verdict([]) == "clean"
    assert compute_verdict(make(Severity.MEDIUM, 2)) == "clean"
    assert compute_verdict(make(Severity.LOW, 10)) == "clean"


def test_suspicious():
    assert compute_verdict(make(Severity.HIGH, 1)) == "suspicious"
    assert compute_verdict(make(Severity.MEDIUM, 3)) == "suspicious"


def test_malicious():
    assert compute_verdict(make(Severity.CRITICAL, 1)) == "malicious"
    assert compute_verdict(make(Severity.HIGH, 2)) == "malicious"
