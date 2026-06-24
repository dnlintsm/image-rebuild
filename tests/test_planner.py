from image_rebuild.models import ScanResult, Vulnerability
from image_rebuild.planner import _max_version, build_plan, detect_os_manager


def _vuln(cve, sev, pkg, installed, fixed, eco):
    return Vulnerability(cve=cve, severity=sev, package=pkg, installed=installed,
                         fixed=fixed, ecosystem=eco)


def test_detect_os_manager():
    assert detect_os_manager("Debian GNU/Linux 11 (bullseye)") == "apt"
    assert detect_os_manager("Ubuntu 22.04.3 LTS") == "apt"
    assert detect_os_manager("Alpine Linux v3.18") == "apk"
    assert detect_os_manager("Red Hat Enterprise Linux 9.2") == "dnf"
    assert detect_os_manager("Amazon Linux 2") == "dnf"
    assert detect_os_manager(None) is None
    assert detect_os_manager("Mystery OS") is None
    assert detect_os_manager("Mystery OS", override="apk") == "apk"


def test_max_version():
    assert _max_version("1.1.1k-1", "1.1.1n-0+deb11u1") == "1.1.1n-0+deb11u1"
    assert _max_version("2.32.0", "2.25.1") == "2.32.0"


def test_plan_groups_os_and_python_channels():
    result = ScanResult(
        image="example/app:1.0",
        distro="Debian GNU/Linux 11 (bullseye)",
        vulnerabilities=[
            _vuln("CVE-1", "critical", "openssl", "1.1.1k-1", "1.1.1n-0+deb11u1", "os"),
            _vuln("CVE-2", "critical", "requests", "2.25.1", "2.32.0", "python"),
        ],
        distribution={"critical": 2},
    )
    plan = build_plan(result)
    managers = {c.manager for c in plan.channels}
    assert managers == {"apt", "pip"}
    assert plan.fixed_cves == ["CVE-1", "CVE-2"]
    assert not plan.blockers
    assert plan.actionable


def test_plan_dedups_package_picking_highest_fix():
    result = ScanResult(
        image="img:tag",
        distro="Debian GNU/Linux 11",
        vulnerabilities=[
            _vuln("CVE-A", "critical", "openssl", "1.1.1k", "1.1.1l", "os"),
            _vuln("CVE-B", "critical", "openssl", "1.1.1k", "1.1.1n", "os"),
        ],
        distribution={"critical": 2},
    )
    plan = build_plan(result)
    apt = next(c for c in plan.channels if c.manager == "apt")
    assert len(apt.fixes) == 1
    fix = apt.fixes[0]
    assert fix.fixed == "1.1.1n"
    assert fix.cves == ["CVE-A", "CVE-B"]


def test_unfixable_becomes_blocker():
    result = ScanResult(
        image="img:tag",
        distro="Debian GNU/Linux 11",
        vulnerabilities=[_vuln("CVE-X", "critical", "zlib1g", "1.2.11", None, "os")],
        distribution={"critical": 1},
    )
    plan = build_plan(result)
    assert not plan.actionable
    assert [v.cve for v in plan.blockers] == ["CVE-X"]


def test_unknown_ecosystem_is_unsupported_not_dropped():
    result = ScanResult(
        image="img:tag",
        distro="Debian GNU/Linux 11",
        vulnerabilities=[_vuln("CVE-J", "critical", "log4j-core", "2.14.1", "2.17.1", "java")],
        distribution={"critical": 1},
    )
    plan = build_plan(result)
    assert not plan.actionable
    assert [v.cve for v in plan.unsupported] == ["CVE-J"]
    assert any("rebuild the app" in r for r in plan.recommendations)


def test_distroless_os_vuln_with_no_manager_is_unsupported():
    result = ScanResult(
        image="distroless:latest",
        distro=None,
        vulnerabilities=[_vuln("CVE-D", "critical", "libc", "1.0", "1.1", "os")],
        distribution={"critical": 1},
    )
    plan = build_plan(result)
    assert plan.os_manager is None
    assert not plan.actionable
    assert [v.cve for v in plan.unsupported] == ["CVE-D"]
