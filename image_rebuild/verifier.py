"""Gate evaluation: does a scan result satisfy the zero-critical policy?

The loop control lives in the orchestrator; this module just turns a ScanResult
into a clear pass/fail verdict against the configured gate severity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import ScanResult, Vulnerability


@dataclass
class GateOutcome:
    passed: bool                              # no vulnerabilities at/above the gate
    gate_severity: str
    count: int                               # number at/above the gate
    blockers: list[Vulnerability] = field(default_factory=list)  # unfixable at gate


def evaluate_gate(result: ScanResult, gate_severity: str = "critical") -> GateOutcome:
    gated = result.at_or_above(gate_severity)
    return GateOutcome(
        passed=not gated,
        gate_severity=gate_severity,
        count=len(gated),
        blockers=[v for v in gated if not v.fixable],
    )
