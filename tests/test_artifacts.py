import json
from datetime import datetime, timezone

from image_rebuild.artifacts import NullArtifacts, RunArtifacts
from image_rebuild.models import ScanResult, Vulnerability
from image_rebuild.orchestrator import CLEAN, RunOutcome


def _result(criticals=0):
    vulns = [
        Vulnerability(cve=f"CVE-{i}", severity="critical", package="p",
                      installed="1", fixed="2", ecosystem="os")
        for i in range(criticals)
    ]
    return ScanResult(image="img:tag", distro="Debian", vulnerabilities=vulns,
                      distribution={"critical": criticals})


def _fixed_clock():
    return datetime(2026, 6, 30, 1, 2, 3, tzinfo=timezone.utc)


def test_null_artifacts_are_noops():
    sink = NullArtifacts()
    sink.record_scan("initial", _result())
    sink.record_dockerfile(1, "FROM x")
    assert sink.finalize(RunOutcome(CLEAN, "img:tag", 1, _result())) is None


def test_run_artifacts_writes_files(tmp_path):
    art = RunArtifacts(str(tmp_path), "registry.io/team/app:1.0", clock=_fixed_clock)
    # Directory name is timestamped and slugged (no '/' or ':').
    assert art.dir.name == "20260630T010203Z_registry.io_team_app_1.0"

    art.record_scan("initial", _result(criticals=2))
    art.record_dockerfile(1, "FROM x\nRUN y\n")
    outcome = RunOutcome(
        CLEAN, "registry.io/team/app:1.0", iterations=1, final_result=_result(0),
        original_digest="sha256:orig", pushed=True, pushed_digest="sha256:new",
        message="done",
    )
    path = art.finalize(outcome)

    assert path == str(art.dir)
    scan = json.loads((art.dir / "scan_initial.json").read_text())
    assert scan["distribution"]["critical"] == 2
    assert len(scan["vulnerabilities"]) == 2
    assert (art.dir / "Dockerfile.1").read_text().startswith("FROM x")
    summary = json.loads((art.dir / "run.json").read_text())
    assert summary["status"] == "clean"
    assert summary["pushed"] is True
    assert summary["pushed_digest"] == "sha256:new"
    assert summary["original_digest"] == "sha256:orig"
    assert summary["final_critical_count"] == 0
