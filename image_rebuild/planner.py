"""Turn a ScanResult into a RemediationPlan.

For each fixable, gate-severity vulnerability we pick a remediation channel:

  - OS packages  -> the distro's package manager (apt / apk / dnf), pinned to
    the fixed version.
  - Python packages -> pip.

Anything else (npm/go/gem/java bundled jars, ...) is routed to `unsupported`
rather than silently dropped: those generally require rebuilding the app, not a
package-manager upgrade, so we surface them for manual attention. Unfixable
gate-severity CVEs become `blockers` (awaiting upstream fix).
"""

from __future__ import annotations

import re

from .models import (
    PackageFix,
    RemediationChannel,
    RemediationPlan,
    ScanResult,
    Vulnerability,
)

# Distro name (from the scan report) -> OS package manager.
_OS_FAMILIES: list[tuple[tuple[str, ...], str]] = [
    (("debian", "ubuntu"), "apt"),
    (("alpine",), "apk"),
    # "redhat"/"amazon" (no space) are Trivy's Metadata.OS.Family spellings.
    (("red hat", "redhat", "rhel", "centos", "rocky", "almalinux", "alma",
      "fedora", "amazon", "oracle"), "dnf"),
]

# Language ecosystem -> package manager. Only ecosystems we can remediate from
# inside the image without rebuilding the app belong here.
_LANG_MANAGERS = {
    "python": "pip",
}


def detect_os_manager(distro: str | None, override: str | None = None) -> str | None:
    """Best-effort map of a distro string to apt/apk/dnf. None if unknown."""
    if override:
        return override
    if not distro:
        return None
    needle = distro.lower()
    for names, manager in _OS_FAMILIES:
        if any(name in needle for name in names):
            return manager
    return None


def _version_key(version: str) -> list[tuple[int, object]]:
    """Loose, dependency-free version sort key.

    Splits into numeric / alphabetic chunks. Numeric chunks compare as ints and
    sort above alphabetic chunks. Good enough to pick the highest required fix
    version; not a full distro version comparator (documented limitation).
    """
    key: list[tuple[int, object]] = []
    for chunk in re.findall(r"\d+|[A-Za-z]+", version):
        if chunk.isdigit():
            key.append((1, int(chunk)))
        else:
            key.append((0, chunk))
    return key


def _max_version(a: str, b: str) -> str:
    """Return the higher of two fix versions (best-effort)."""
    return a if _version_key(a) >= _version_key(b) else b


def build_plan(
    result: ScanResult,
    gate_severity: str = "critical",
    package_manager: str | None = None,
    base_image: str | None = None,
) -> RemediationPlan:
    os_manager = detect_os_manager(result.distro, package_manager)
    gated = result.at_or_above(gate_severity)

    blockers = [v for v in gated if not v.fixable]
    fixable = [v for v in gated if v.fixable]

    unsupported: list[Vulnerability] = []
    # (manager, ecosystem) -> { package -> (fixed_version, {cves}) }
    grouped: dict[tuple[str, str], dict[str, tuple[str, set[str]]]] = {}

    for vuln in fixable:
        if vuln.ecosystem == "os":
            if os_manager is None:
                # No package manager (distroless/scratch or unknown distro):
                # OS CVEs can't be remediated here. Surface, don't drop.
                unsupported.append(vuln)
                continue
            manager, ecosystem = os_manager, "os"
        elif vuln.ecosystem in _LANG_MANAGERS:
            manager, ecosystem = _LANG_MANAGERS[vuln.ecosystem], vuln.ecosystem
        else:
            unsupported.append(vuln)
            continue

        packages = grouped.setdefault((manager, ecosystem), {})
        if vuln.package in packages:
            cur_fixed, cves = packages[vuln.package]
            packages[vuln.package] = (
                _max_version(cur_fixed, vuln.fixed or cur_fixed),
                cves | {vuln.cve},
            )
        else:
            packages[vuln.package] = (vuln.fixed or "", {vuln.cve})

    channels: list[RemediationChannel] = []
    for (manager, ecosystem), packages in grouped.items():
        fixes = [
            PackageFix(package=name, fixed=fixed, cves=sorted(cves))
            for name, (fixed, cves) in sorted(packages.items())
        ]
        channels.append(RemediationChannel(manager=manager, ecosystem=ecosystem, fixes=fixes))
    channels.sort(key=lambda c: (c.ecosystem, c.manager))

    recommendations: list[str] = []
    os_fix_count = sum(len(c.fixes) for c in channels if c.ecosystem == "os")
    if os_fix_count:
        recommendations.append(
            f"{os_fix_count} OS package(s) patched in-place; consider rebasing to a "
            "newer patched base image as a more durable fix (recommendation only)."
        )
    if unsupported:
        recommendations.append(
            f"{len(unsupported)} fixable CVE(s) are in ecosystems this tool does not "
            "auto-remediate (e.g. bundled jars, npm/go) — rebuild the app with the "
            "fixed dependency versions."
        )

    return RemediationPlan(
        image=result.image,
        base_image=base_image or result.image,
        os_manager=os_manager,
        channels=channels,
        blockers=blockers,
        unsupported=unsupported,
        recommendations=recommendations,
    )
