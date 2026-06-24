"""Confirm the parser + planner against a realistic, docs-grounded twistcli report.

The fixture mirrors the actual `twistcli images scan --output-file` shape: the
documented result fields (id/name/distro/distroRelease/digest/collections) plus
the fields the real binary emits beyond the simplified docs schema
(packageType, vulnerabilityDistribution, riskFactors as an object, fixDate,
vector, tags).
"""

from pathlib import Path

import pytest

from image_rebuild.parser import parse_report_file
from image_rebuild.planner import build_plan

FIXTURE = Path(__file__).parent / "fixtures" / "twistcli_real_sample.json"


@pytest.fixture
def result():
    return parse_report_file(FIXTURE)


def test_parses_real_shape(result):
    assert result.image == "registry.example.com/team/api:2.3.1"
    assert result.distro == "Ubuntu 22.04.3 LTS"
    assert result.distribution["critical"] == 2
    assert result.critical_count == 2
    assert len(result.vulnerabilities) == 5


def test_status_fix_extraction_and_ecosystem(result):
    by_pkg = {v.package: v for v in result.vulnerabilities}
    assert by_pkg["openssl"].fixed == "3.0.2-0ubuntu1.12"
    assert by_pkg["openssl"].ecosystem == "os"
    assert by_pkg["idna"].ecosystem == "python"
    assert by_pkg["log4j-core"].ecosystem == "jar"
    # "needed" means no upstream fix yet
    assert by_pkg["gnupg2"].fixed is None
    assert by_pkg["gnupg2"].fixable is False


def test_critical_gate_plan_is_fully_actionable(result):
    plan = build_plan(result, gate_severity="critical")
    assert plan.os_manager == "apt"
    managers = {c.manager for c in plan.channels}
    assert managers == {"apt", "pip"}
    assert plan.fixed_cves == ["CVE-2023-4807", "CVE-2024-3651"]
    assert not plan.blockers
    assert not plan.unsupported
    assert plan.actionable


def test_high_gate_surfaces_blocker_and_unsupported(result):
    plan = build_plan(result, gate_severity="high")
    # gnupg2 high has no fix -> blocker; log4j (jar) is fixable but needs app rebuild
    assert [v.cve for v in plan.blockers] == ["CVE-2022-3219"]
    assert [v.cve for v in plan.unsupported] == ["CVE-2021-44228"]
