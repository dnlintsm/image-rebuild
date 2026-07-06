import json

import pytest

from image_rebuild import scanner as scanner_mod
from image_rebuild.scanner import ScannerError, TrivyScanner


def test_trivy_missing_binary(monkeypatch):
    monkeypatch.setattr(scanner_mod.shutil, "which", lambda name: None)
    with pytest.raises(ScannerError, match="not found on PATH"):
        TrivyScanner().scan("img:tag")


def _fake_run(record, returncode=0, write_report=True):
    class Proc:
        pass

    def run(cmd, capture_output, text, check):
        record.append(cmd)
        if write_report:
            out = cmd[cmd.index("--output") + 1]
            report = {
                "SchemaVersion": 2,
                "ArtifactName": "img:tag",
                "Metadata": {"OS": {"Family": "alpine", "Name": "3.19"}},
                "Results": [{
                    "Class": "os-pkgs", "Type": "alpine",
                    "Vulnerabilities": [{
                        "VulnerabilityID": "CVE-1", "PkgName": "musl",
                        "InstalledVersion": "1.2.4", "FixedVersion": "1.2.5",
                        "Severity": "CRITICAL",
                    }],
                }],
            }
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(report, fh)
        proc = Proc()
        proc.returncode = returncode
        proc.stdout = ""
        proc.stderr = "boom" if returncode else ""
        return proc

    return run


def test_trivy_scan_builds_command_and_parses(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    calls = []
    monkeypatch.setattr(scanner_mod.subprocess, "run", _fake_run(calls))

    report = tmp_path / "report.json"
    result = TrivyScanner().scan("img:tag", save_report_to=str(report))

    cmd = calls[0]
    assert cmd[:2] == ["trivy", "image"]
    assert cmd[-1] == "img:tag"
    assert "--format" in cmd and "json" in cmd
    assert "vuln" in cmd  # secrets/misconfig scanning skipped
    assert report.exists()

    assert result.image == "img:tag"
    assert result.distro == "alpine 3.19"
    assert result.critical_count == 1
    assert result.vulnerabilities[0].fixed == "1.2.5"


def test_trivy_nonzero_exit_is_an_error(monkeypatch):
    monkeypatch.setattr(scanner_mod.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(
        scanner_mod.subprocess, "run",
        _fake_run([], returncode=1, write_report=False),
    )
    with pytest.raises(ScannerError, match="trivy scan of img:tag failed: boom"):
        TrivyScanner().scan("img:tag")
