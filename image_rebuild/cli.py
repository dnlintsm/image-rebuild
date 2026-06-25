"""Command-line entrypoint.

  scan       — scan an image (or parse a twistcli report) and print findings.
  fix        — plan + generate (--dry-run), or run the build+verify loop.
"""

from __future__ import annotations

import argparse
import logging
import sys

from .builder import BuildError, DockerBuilder
from .config import ConfigError, PrismaConfig
from .generator import generate_dockerfile
from .models import RemediationPlan, ScanResult, severity_rank
from .orchestrator import Orchestrator, RunOutcome
from .parser import parse_report_file
from .planner import build_plan
from .scanner import PrismaScanner, ScannerError

# Exit codes (see DESIGN.md §7).
EXIT_OK = 0
EXIT_CRITICALS = 1
EXIT_SCANNER = 2
EXIT_CONFIG = 3


def _format_table(vulns: list, limit: int | None = None) -> str:
    rows = [("SEVERITY", "CVE", "PACKAGE", "INSTALLED", "FIXED", "ECOSYSTEM")]
    shown = vulns if limit is None else vulns[:limit]
    for v in shown:
        rows.append((
            v.severity.upper(),
            v.cve,
            v.package,
            v.installed or "-",
            v.fixed or "(no fix)",
            v.ecosystem,
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for idx, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if idx == 0:
            lines.append("  ".join("-" * widths[i] for i in range(len(widths))))
    if limit is not None and len(vulns) > limit:
        lines.append(f"... and {len(vulns) - limit} more")
    return "\n".join(lines)


def _print_summary(result: ScanResult, gate: str) -> None:
    dist = result.distribution
    order = ["critical", "high", "medium", "low"]
    counts = "  ".join(
        f"{sev}={dist.get(sev, sum(1 for v in result.vulnerabilities if v.severity == sev))}"
        for sev in order
    )
    print(f"\nImage:  {result.image}")
    if result.distro:
        print(f"Distro: {result.distro}")
    print(f"Totals: {counts}  (total={len(result.vulnerabilities)})")

    gated = result.at_or_above(gate)
    blockers = result.blockers(gate)
    print(f"\n{gate.capitalize()}+ vulnerabilities ({len(gated)}):")
    if gated:
        print(_format_table(gated, limit=50))
    else:
        print("  none")

    if blockers:
        print(
            f"\n[BLOCKED] {len(blockers)} {gate}+ CVE(s) have no upstream fix "
            "(awaiting upstream fix):"
        )
        for v in blockers:
            print(f"  - {v.cve}  {v.package} {v.installed}")


def _load_result(args: argparse.Namespace) -> ScanResult:
    """Obtain a ScanResult from --report (offline) or a live Prisma scan."""
    if args.report:
        return parse_report_file(args.report, image_fallback=args.image)
    if not args.image:
        raise ConfigError("provide an IMAGE to scan, or --report FILE")
    scanner = PrismaScanner(PrismaConfig.from_env())
    return scanner.scan(args.image, save_report_to=getattr(args, "save_report", None))


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        result = _load_result(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScannerError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return EXIT_SCANNER

    _print_summary(result, gate=args.gate_severity)

    if args.fail_on_gate and result.at_or_above(args.gate_severity):
        return EXIT_CRITICALS
    return EXIT_OK


def _print_plan(plan: RemediationPlan) -> None:
    print(f"\nRemediation plan for {plan.image}")
    print(f"OS package manager: {plan.os_manager or '(none detected)'}")
    if plan.channels:
        print(f"\nAuto-fixable ({len(plan.fixed_cves)} CVE(s)):")
        for channel in plan.channels:
            print(f"  [{channel.ecosystem} / {channel.manager}]")
            for fix in channel.fixes:
                print(f"    {fix.package} -> {fix.fixed}  ({', '.join(fix.cves)})")
    else:
        print("\nAuto-fixable: none")

    if plan.blockers:
        print(f"\n[BLOCKED] {len(plan.blockers)} CVE(s) with no upstream fix (awaiting upstream):")
        for v in plan.blockers:
            print(f"  - {v.cve}  {v.package} {v.installed}")
    if plan.unsupported:
        print(f"\n[MANUAL] {len(plan.unsupported)} fixable CVE(s) need an app rebuild (no in-image channel):")
        for v in plan.unsupported:
            print(f"  - {v.cve}  {v.package} {v.installed} -> {v.fixed}  [{v.ecosystem}]")
    for rec in plan.recommendations:
        print(f"\n* {rec}")


def _print_outcome(outcome: RunOutcome) -> None:
    print(f"\nResult: {outcome.status.upper()} — {outcome.message}")
    print(f"Image:  {outcome.image}")
    print(f"Iterations: {outcome.iterations}")
    print(f"Remaining {outcome.final_result.critical_count} critical "
          f"(total {len(outcome.final_result.vulnerabilities)})")
    if outcome.blockers:
        print(f"\n[BLOCKED] {len(outcome.blockers)} CVE(s) awaiting an upstream fix:")
        for v in outcome.blockers:
            print(f"  - {v.cve}  {v.package} {v.installed}")
    if outcome.unsupported:
        print(f"\n[MANUAL] {len(outcome.unsupported)} CVE(s) need an app rebuild:")
        for v in outcome.unsupported:
            print(f"  - {v.cve}  {v.package} {v.installed} -> {v.fixed}  [{v.ecosystem}]")


def _cmd_fix(args: argparse.Namespace) -> int:
    if not args.dry_run:
        return _run_fix_loop(args)

    try:
        result = _load_result(args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScannerError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return EXIT_SCANNER

    plan = build_plan(
        result,
        gate_severity=args.gate_severity,
        package_manager=args.package_manager,
        base_image=args.base_image,
    )
    _print_plan(plan)

    # The gate is only clearable if every gate-severity CVE has an auto-fix
    # channel — anything left in blockers (no upstream fix) or unsupported
    # (needs an app rebuild) means a rebuild from this plan still won't pass.
    gate_unclearable = plan.has_blockers or bool(plan.unsupported)

    if not plan.actionable:
        print("\nNo auto-remediable vulnerabilities — no Dockerfile generated.")
        return EXIT_CRITICALS if gate_unclearable else EXIT_OK

    dockerfile = generate_dockerfile(plan)
    print("\n--- generated Dockerfile ---")
    print(dockerfile, end="")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(dockerfile)
        print(f"--- written to {args.output} ---")

    if gate_unclearable:
        print(
            "\nWARNING: some gate-severity CVEs cannot be auto-remediated "
            "(see [BLOCKED]/[MANUAL] above) — the rebuilt image would not pass the gate."
        )
    return EXIT_CRITICALS if gate_unclearable else EXIT_OK


def _run_fix_loop(args: argparse.Namespace) -> int:
    """Live build + verify loop (M3): pull, scan, fix, rebuild, re-scan."""
    if args.report:
        print("error: --report is for offline planning; the build+verify loop needs "
              "a live image. Use --dry-run with --report, or pass an IMAGE.",
              file=sys.stderr)
        return EXIT_CONFIG
    if not args.image:
        print("error: provide an IMAGE to fix (or use --dry-run --report FILE).",
              file=sys.stderr)
        return EXIT_CONFIG
    if args.push:
        print("error: --push (publishing) lands in M4 and is not implemented yet.",
              file=sys.stderr)
        return EXIT_CONFIG

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        orchestrator = Orchestrator(
            scanner=PrismaScanner(PrismaConfig.from_env()),
            builder=DockerBuilder(),
            gate_severity=args.gate_severity,
            max_iterations=args.max_iterations,
            package_manager=args.package_manager,
        )
        outcome = orchestrator.run(args.image)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except ScannerError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return EXIT_SCANNER
    except BuildError as exc:
        print(f"build error: {exc}", file=sys.stderr)
        return EXIT_SCANNER

    _print_outcome(outcome)
    return EXIT_OK if outcome.passed else EXIT_CRITICALS


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="image-rebuild",
        description="Scan Docker images with Prisma Cloud and rebuild to zero critical CVEs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan an image (or parse an existing report) and print findings.")
    scan.add_argument("image", nargs="?", help="Image reference, e.g. nginx:1.25")
    scan.add_argument("--report", help="Parse an existing twistcli JSON report instead of scanning.")
    scan.add_argument("--save-report", help="Path to also save the raw twistcli JSON report.")
    scan.add_argument("--gate-severity", default="critical",
                      help="Severity gate to highlight/fail on (default: critical).")
    scan.add_argument("--fail-on-gate", action="store_true",
                      help="Exit non-zero if any vulnerability at/above the gate severity is found.")
    scan.set_defaults(func=_cmd_scan)

    fix = sub.add_parser("fix", help="Plan and (with --dry-run) generate a remediation Dockerfile.")
    fix.add_argument("image", nargs="?", help="Image reference, e.g. nginx:1.25")
    fix.add_argument("--report", help="Parse an existing twistcli JSON report instead of scanning.")
    fix.add_argument("--save-report", help="Path to also save the raw twistcli JSON report.")
    fix.add_argument("--dry-run", action="store_true",
                     help="Generate the remediation Dockerfile without building or pushing.")
    fix.add_argument("--output", "-o", help="Write the generated Dockerfile to this path (dry-run).")
    fix.add_argument("--gate-severity", default="critical",
                     help="Severity gate to remediate (default: critical).")
    fix.add_argument("--package-manager", choices=["apt", "apk", "dnf"],
                     help="Override OS package-manager detection.")
    fix.add_argument("--base-image", help="Override the FROM target (e.g. pin to a digest).")
    fix.add_argument("--max-iterations", type=int, default=3,
                     help="Max rebuild/re-scan iterations in the build loop (default: 3).")
    fix.add_argument("--push", action="store_true",
                     help="Push the cleared image to the registry (M4; not yet implemented).")
    fix.set_defaults(func=_cmd_fix)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Validate gate severity early.
    if severity_rank(args.gate_severity) == 0 and args.gate_severity.lower() != "unknown":
        parser.error(f"unknown --gate-severity: {args.gate_severity}")
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
