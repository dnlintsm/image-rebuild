from pathlib import Path

import pytest

from image_rebuild.models import severity_rank
from image_rebuild.parser import parse_report, parse_report_file

FIXTURE = Path(__file__).parent / "fixtures" / "twistcli_sample.json"


@pytest.fixture
def result():
    return parse_report_file(FIXTURE)


def test_basic_fields(result):
    assert result.image == "example/app:1.0"
    assert result.distro.startswith("Debian")
    assert len(result.vulnerabilities) == 4


def test_distribution_and_critical_count(result):
    assert result.distribution["critical"] == 2
    assert result.critical_count == 2


def test_fixed_version_parsed_from_status(result):
    openssl = next(v for v in result.vulnerabilities if v.package == "openssl")
    assert openssl.fixed == "1.1.1n-0+deb11u1"
    assert openssl.fixable is True


def test_open_status_means_no_fix(result):
    zlib = next(v for v in result.vulnerabilities if v.package == "zlib1g")
    assert zlib.fixed is None
    assert zlib.fixable is False


def test_ecosystem_mapping(result):
    eco = {v.package: v.ecosystem for v in result.vulnerabilities}
    assert eco["openssl"] == "os"
    assert eco["requests"] == "python"
    assert eco["log4j-core"] == "java"


def test_at_or_above_sorts_by_severity_then_cvss(result):
    criticals = result.at_or_above("critical")
    assert [v.cve for v in criticals] == ["CVE-2024-0002", "CVE-2024-0001"]
    # high gate pulls in the high finding too
    assert len(result.at_or_above("high")) == 3


def test_blockers_are_unfixable_at_gate():
    raw = {
        "results": [{
            "name": "img:tag",
            "vulnerabilities": [
                {"id": "C1", "severity": "critical", "packageName": "p1",
                 "packageVersion": "1", "status": "open", "packageType": "os"},
                {"id": "C2", "severity": "critical", "packageName": "p2",
                 "packageVersion": "1", "status": "fixed in 2", "packageType": "os"},
            ],
        }]
    }
    result = parse_report(raw)
    blockers = result.blockers("critical")
    assert [v.cve for v in blockers] == ["C1"]


def test_empty_report_is_clean():
    result = parse_report({"results": [{"name": "x:y", "vulnerabilities": []}]})
    assert result.critical_count == 0
    assert result.at_or_above("critical") == []


def test_severity_rank_ordering():
    assert severity_rank("critical") > severity_rank("high") > severity_rank("low")
    assert severity_rank("bogus") == 0
