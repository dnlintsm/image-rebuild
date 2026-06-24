from image_rebuild.models import ScanResult, Vulnerability
from image_rebuild.verifier import evaluate_gate


def _v(cve, sev, fixed):
    return Vulnerability(cve=cve, severity=sev, package="p", installed="1",
                         fixed=fixed, ecosystem="os")


def _result(vulns):
    return ScanResult(image="i", distro="Debian", vulnerabilities=vulns, distribution={})


def test_passes_when_no_gate_vulns():
    out = evaluate_gate(_result([_v("C", "high", "2")]), gate_severity="critical")
    assert out.passed
    assert out.count == 0
    assert out.blockers == []


def test_fails_with_count_and_blockers():
    out = evaluate_gate(
        _result([_v("C1", "critical", "2"), _v("C2", "critical", None)]),
        gate_severity="critical",
    )
    assert not out.passed
    assert out.count == 2
    assert [v.cve for v in out.blockers] == ["C2"]
