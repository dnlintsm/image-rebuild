"""Normalized data model shared across the pipeline.

Scanner-agnostic on purpose: the parser maps Prisma/twistcli output into these
types, and every downstream module (planner, verifier, ...) works against them
so the scanner can be swapped later.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Higher number = more severe. Unknown severities sort below "low".
SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "moderate": 3,
    "low": 2,
    "negligible": 1,
    "unknown": 0,
}


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.lower(), 0)


@dataclass
class Vulnerability:
    """A single CVE against a single package in the scanned image."""

    cve: str
    severity: str            # normalized lower-case (critical/high/medium/low/...)
    package: str
    installed: str
    fixed: str | None        # fixed version, or None when no upstream fix exists
    ecosystem: str           # os | python | nodejs | go | gem | ... | unknown
    cvss: float | None = None
    link: str | None = None

    @property
    def fixable(self) -> bool:
        return bool(self.fixed)


@dataclass
class ScanResult:
    """The normalized outcome of one scan."""

    image: str
    vulnerabilities: list[Vulnerability]
    distribution: dict[str, int] = field(default_factory=dict)
    distro: str | None = None

    def _count(self, severity: str) -> int:
        # Trust the scanner's own distribution counts when present; otherwise
        # derive from the vulnerability list.
        if severity in self.distribution:
            return self.distribution[severity]
        return sum(1 for v in self.vulnerabilities if v.severity == severity)

    @property
    def critical_count(self) -> int:
        return self._count("critical")

    def at_or_above(self, severity: str) -> list[Vulnerability]:
        """Vulnerabilities at least as severe as `severity`, most severe first."""
        threshold = severity_rank(severity)
        out = [v for v in self.vulnerabilities if severity_rank(v.severity) >= threshold]
        out.sort(key=lambda v: (severity_rank(v.severity), v.cvss or 0.0), reverse=True)
        return out

    def blockers(self, severity: str = "critical") -> list[Vulnerability]:
        """Gate-severity vulnerabilities with no available fix (awaiting upstream)."""
        return [v for v in self.at_or_above(severity) if not v.fixable]
