"""The remediation loop: pull, scan, fix, rebuild, re-scan until the gate passes.

Scanner and builder are injected (Protocols), so the loop logic is fully
unit-testable without a Docker daemon or twistcli — production wires in
PrismaScanner + DockerBuilder, tests pass fakes.

Termination:
  - already clean        -> ALREADY_CLEAN (no build)
  - reaches zero at gate -> CLEAN
  - nothing auto-fixable -> BLOCKED (unfixable/unsupported gate CVEs remain)
  - count stops dropping -> STALLED
  - hits max_iterations  -> STALLED
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

from .builder import ImageBuilder
from .generator import generate_dockerfile
from .models import ScanResult, Vulnerability
from .planner import build_plan
from .verifier import evaluate_gate

logger = logging.getLogger("image_rebuild")


class Scanner(Protocol):
    def scan(self, image: str, save_report_to: str | None = None) -> ScanResult: ...


# Outcome statuses.
ALREADY_CLEAN = "already_clean"
CLEAN = "clean"
BLOCKED = "blocked"
STALLED = "stalled"

_PASSING = {ALREADY_CLEAN, CLEAN}


@dataclass
class RunOutcome:
    status: str
    image: str
    iterations: int
    final_result: ScanResult
    dockerfiles: list[str] = field(default_factory=list)
    blockers: list[Vulnerability] = field(default_factory=list)
    unsupported: list[Vulnerability] = field(default_factory=list)
    message: str = ""

    @property
    def passed(self) -> bool:
        return self.status in _PASSING


class Orchestrator:
    def __init__(
        self,
        scanner: Scanner,
        builder: ImageBuilder,
        gate_severity: str = "critical",
        max_iterations: int = 3,
        package_manager: str | None = None,
    ):
        self.scanner = scanner
        self.builder = builder
        self.gate_severity = gate_severity
        self.max_iterations = max_iterations
        self.package_manager = package_manager

    def run(self, image: str) -> RunOutcome:
        logger.info("Pulling %s", image)
        self.builder.pull(image)

        logger.info("Scanning %s", image)
        result = self.scanner.scan(image)
        outcome = evaluate_gate(result, self.gate_severity)
        if outcome.passed:
            logger.info("%s already passes the %s gate", image, self.gate_severity)
            return RunOutcome(
                status=ALREADY_CLEAN, image=image, iterations=0, final_result=result,
                message=f"No {self.gate_severity} vulnerabilities — nothing to fix.",
            )

        dockerfiles: list[str] = []
        prev_count = outcome.count

        for iteration in range(1, self.max_iterations + 1):
            plan = build_plan(
                result,
                gate_severity=self.gate_severity,
                package_manager=self.package_manager,
                base_image=image,
            )

            if not plan.actionable:
                logger.warning(
                    "Iteration %d: no auto-remediable %s CVEs remain",
                    iteration, self.gate_severity,
                )
                return RunOutcome(
                    status=BLOCKED, image=image, iterations=iteration - 1,
                    final_result=result, dockerfiles=dockerfiles,
                    blockers=plan.blockers, unsupported=plan.unsupported,
                    message=self._blocked_message(plan.blockers, plan.unsupported),
                )

            original_user = self.builder.inspect_user(image)
            dockerfile = generate_dockerfile(plan, original_user=original_user)
            dockerfiles.append(dockerfile)

            logger.info(
                "Iteration %d: rebuilding %s to fix %d CVE(s)",
                iteration, image, len(plan.fixed_cves),
            )
            self.builder.build(dockerfile, image)

            result = self.scanner.scan(image)
            outcome = evaluate_gate(result, self.gate_severity)
            if outcome.passed:
                logger.info("Gate cleared after %d iteration(s)", iteration)
                return RunOutcome(
                    status=CLEAN, image=image, iterations=iteration,
                    final_result=result, dockerfiles=dockerfiles,
                    message=f"Cleared the {self.gate_severity} gate after "
                            f"{iteration} iteration(s).",
                )

            if outcome.count >= prev_count:
                logger.warning(
                    "Iteration %d made no progress (%d -> %d); stopping",
                    iteration, prev_count, outcome.count,
                )
                return RunOutcome(
                    status=STALLED, image=image, iterations=iteration,
                    final_result=result, dockerfiles=dockerfiles,
                    blockers=outcome.blockers,
                    message=f"Stalled: {outcome.count} {self.gate_severity} "
                            "CVE(s) remain and the count stopped dropping.",
                )
            prev_count = outcome.count

        return RunOutcome(
            status=STALLED, image=image, iterations=self.max_iterations,
            final_result=result, dockerfiles=dockerfiles,
            blockers=outcome.blockers,
            message=f"Stalled: {outcome.count} {self.gate_severity} CVE(s) remain "
                    f"after {self.max_iterations} iteration(s).",
        )

    @staticmethod
    def _blocked_message(blockers, unsupported) -> str:
        parts = []
        if blockers:
            parts.append(f"{len(blockers)} awaiting an upstream fix")
        if unsupported:
            parts.append(f"{len(unsupported)} needing an app rebuild")
        detail = "; ".join(parts) if parts else "no remediable CVEs"
        return f"Blocked — cannot reach zero ({detail})."
