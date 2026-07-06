from pathlib import Path

import pytest

from image_rebuild.parser import is_trivy_report, parse_report_file, parse_trivy_report
from image_rebuild.planner import detect_os_manager

FIXTURE = Path(__file__).parent / "fixtures" / "trivy_sample.json"


@pytest.fixture
def result():
    return parse_report_file(FIXTURE)


def test_report_file_autodetects_trivy(result):
    # parse_report_file dispatches on the schema, no flag needed.
    assert result.image == "example/app:1.0"
    assert len(result.vulnerabilities) == 5


def test_distro_from_metadata(result):
    assert result.distro == "debian 12.5"
    assert detect_os_manager(result.distro) == "apt"


def test_counts_derived_without_distribution(result):
    # Trivy has no summary block; counts come from the vulnerability list.
    assert result.distribution == {}
    assert result.critical_count == 3


def test_severity_normalized_lowercase(result):
    assert {v.severity for v in result.vulnerabilities} == {"critical", "high", "medium"}


def test_ecosystem_mapping(result):
    eco = {v.package: v.ecosystem for v in result.vulnerabilities}
    assert eco["openssl"] == "os"
    assert eco["requests"] == "python"
    assert eco["com.fasterxml.jackson.core:jackson-databind"] == "java"


def test_missing_fixed_version_means_no_fix(result):
    libxml2 = next(v for v in result.vulnerabilities if v.package == "libxml2")
    assert libxml2.fixed is None
    assert libxml2.fixable is False


def test_multiple_fixed_versions_pin_to_first(result):
    zlib = next(v for v in result.vulnerabilities if v.package == "zlib1g")
    assert zlib.fixed == "1:1.2.13.dfsg-1+deb12u1"


def test_cvss_takes_max_v3_across_sources(result):
    openssl = next(v for v in result.vulnerabilities if v.package == "openssl")
    assert openssl.cvss == 9.8
    # V2 fallback when no V3 score exists.
    libxml2 = next(v for v in result.vulnerabilities if v.package == "libxml2")
    assert libxml2.cvss == 7.5


def test_is_trivy_report_detection():
    assert is_trivy_report({"SchemaVersion": 2, "Results": []})
    assert not is_trivy_report({"results": [{"vulnerabilities": []}]})


def test_empty_results_yields_clean_result():
    result = parse_trivy_report({"SchemaVersion": 2}, image_fallback="img:tag")
    assert result.image == "img:tag"
    assert result.vulnerabilities == []
    assert result.critical_count == 0
