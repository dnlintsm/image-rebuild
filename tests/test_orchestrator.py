from image_rebuild.models import ScanResult, Vulnerability
from image_rebuild.orchestrator import (
    ALREADY_CLEAN,
    BLOCKED,
    CLEAN,
    STALLED,
    Orchestrator,
)


def _result(vulns):
    return ScanResult(image="img:tag", distro="Debian GNU/Linux 11",
                      vulnerabilities=vulns, distribution={})


def _crit(cve, pkg="openssl", fixed="1.1.1n", eco="os"):
    return Vulnerability(cve=cve, severity="critical", package=pkg,
                         installed="1.1.1k", fixed=fixed, ecosystem=eco)


class FakeScanner:
    """Returns scripted ScanResults, one per scan() call."""

    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    def scan(self, image, save_report_to=None):
        self.calls += 1
        # Repeat the last result if over-called.
        idx = min(self.calls - 1, len(self._results) - 1)
        return self._results[idx]


class FakeBuilder:
    def __init__(self):
        self.pulls = []
        self.builds = []

    def pull(self, image):
        self.pulls.append(image)

    def build(self, dockerfile_text, tag):
        self.builds.append((tag, dockerfile_text))
        return tag

    def inspect_user(self, image):
        return None


def test_already_clean_does_not_build():
    scanner = FakeScanner([_result([])])
    builder = FakeBuilder()
    outcome = Orchestrator(scanner, builder).run("img:tag")
    assert outcome.status == ALREADY_CLEAN
    assert outcome.iterations == 0
    assert builder.builds == []
    assert outcome.passed


def test_single_pass_fix_clears_gate():
    # First scan: 1 fixable critical. After one rebuild: clean.
    scanner = FakeScanner([_result([_crit("CVE-1")]), _result([])])
    builder = FakeBuilder()
    outcome = Orchestrator(scanner, builder).run("img:tag")
    assert outcome.status == CLEAN
    assert outcome.iterations == 1
    assert len(builder.builds) == 1
    assert len(outcome.dockerfiles) == 1
    assert "openssl=1.1.1n" in outcome.dockerfiles[0]
    assert outcome.passed


def test_unfixable_critical_is_blocked_without_building():
    scanner = FakeScanner([_result([_crit("CVE-X", fixed=None)])])
    builder = FakeBuilder()
    outcome = Orchestrator(scanner, builder).run("img:tag")
    assert outcome.status == BLOCKED
    assert builder.builds == []
    assert [v.cve for v in outcome.blockers] == ["CVE-X"]
    assert not outcome.passed


def test_unsupported_ecosystem_is_blocked():
    scanner = FakeScanner([_result([_crit("CVE-J", pkg="log4j-core", fixed="2.17.1", eco="jar")])])
    outcome = Orchestrator(scanner, FakeBuilder()).run("img:tag")
    assert outcome.status == BLOCKED
    assert [v.cve for v in outcome.unsupported] == ["CVE-J"]


def test_no_progress_stalls():
    # Every scan returns the same single fixable critical -> count never drops.
    scanner = FakeScanner([_result([_crit("CVE-1")])])
    builder = FakeBuilder()
    outcome = Orchestrator(scanner, builder, max_iterations=3).run("img:tag")
    assert outcome.status == STALLED
    assert outcome.iterations == 1  # bails as soon as count doesn't drop
    assert not outcome.passed


def test_multi_pass_progress_then_clean():
    # 2 criticals -> after first rebuild 1 -> after second rebuild 0.
    scanner = FakeScanner([
        _result([_crit("CVE-1"), _crit("CVE-2", pkg="zlib1g", fixed="1.2.13")]),
        _result([_crit("CVE-2", pkg="zlib1g", fixed="1.2.13")]),
        _result([]),
    ])
    builder = FakeBuilder()
    outcome = Orchestrator(scanner, builder, max_iterations=3).run("img:tag")
    assert outcome.status == CLEAN
    assert outcome.iterations == 2
    assert len(builder.builds) == 2
