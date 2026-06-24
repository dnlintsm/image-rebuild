"""Parse a Prisma Cloud Compute (twistcli) JSON report into the normalized model.

Written defensively against the documented twistcli `--output-file` schema:

    {
      "results": [{
        "name": "image:tag",
        "distro": "Debian GNU/Linux 11 (bullseye)",
        "vulnerabilityDistribution": {"critical": 1, "high": 2, ...},
        "vulnerabilities": [{
          "id": "CVE-2024-XXXX",
          "severity": "critical",
          "packageName": "openssl",
          "packageVersion": "1.1.1k-1",
          "status": "fixed in 1.1.1n-0+deb11u1",   // may be "" / "open" / "needed"
          "packageType": "os",                       // os | python | nodejs | ...
          "cvss": 9.8,
          "link": "https://..."
        }]
      }]
    }

Field names are confirmed against a real Console sample before M1 ships (see
DESIGN.md §10); until then the parser tolerates the common variants.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .models import ScanResult, Vulnerability

_FIXED_IN_RE = re.compile(r"fixed in\s+(.+)", re.IGNORECASE)

# twistcli `status` values that mean "no fix available".
_NO_FIX_STATUSES = {"", "open", "affected", "needed", "deferred", "will not fix", "wont fix"}


def _parse_fixed(vuln: dict) -> str | None:
    """Extract the fixed version, or None when no upstream fix exists."""
    # Explicit fields take precedence if a future schema provides them.
    for key in ("fixedVersion", "fixed_version", "fixVersion"):
        val = vuln.get(key)
        if val:
            return str(val).strip()

    status = str(vuln.get("status") or "").strip()
    match = _FIXED_IN_RE.search(status)
    if match:
        return match.group(1).strip()
    if status.lower() in _NO_FIX_STATUSES:
        return None
    # A bare version string in `status` is treated as the fix version.
    if status and not status.lower().startswith(("open", "affected", "needed")):
        return status
    return None


def _ecosystem(vuln: dict) -> str:
    eco = vuln.get("packageType") or vuln.get("type") or "unknown"
    return str(eco).strip().lower() or "unknown"


def _to_vulnerability(vuln: dict) -> Vulnerability:
    cvss = vuln.get("cvss")
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    return Vulnerability(
        cve=str(vuln.get("id") or vuln.get("cve") or "UNKNOWN"),
        severity=str(vuln.get("severity") or "unknown").strip().lower(),
        package=str(vuln.get("packageName") or vuln.get("package") or "unknown"),
        installed=str(vuln.get("packageVersion") or vuln.get("version") or ""),
        fixed=_parse_fixed(vuln),
        ecosystem=_ecosystem(vuln),
        cvss=cvss,
        link=vuln.get("link"),
    )


def parse_report(raw: dict, image_fallback: str | None = None) -> ScanResult:
    """Normalize a parsed twistcli JSON document into a ScanResult."""
    results = raw.get("results") or []
    if not results:
        # Some report variants put the body at the top level.
        result = raw if "vulnerabilities" in raw else {}
    else:
        result = results[0]

    raw_vulns = result.get("vulnerabilities") or []
    vulnerabilities = [_to_vulnerability(v) for v in raw_vulns]

    distribution = {
        k.lower(): int(v)
        for k, v in (result.get("vulnerabilityDistribution") or {}).items()
        if isinstance(v, (int, float))
    }

    image = result.get("name") or image_fallback or "unknown"
    return ScanResult(
        image=str(image),
        vulnerabilities=vulnerabilities,
        distribution=distribution,
        distro=result.get("distro"),
    )


def parse_report_file(path: str | Path, image_fallback: str | None = None) -> ScanResult:
    """Load and parse a twistcli JSON report from disk."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_report(raw, image_fallback=image_fallback)
