"""Command-line entrypoint.

M1 ships the `scan` subcommand: scan an image with Prisma (or parse an existing
twistcli report) and print a normalized vulnerability summary.
"""

from __future__ import annotations

import argparse
import sys

from .config import ConfigError, PrismaConfig
from .models import ScanResult, severity_rank
from .parser import parse_report_file
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


def _cmd_scan(args: argparse.Namespace) -> int:
    try:
        if args.report:
            result = parse_report_file(args.report, image_fallback=args.image)
        else:
            if not args.image:
                print("error: provide an IMAGE to scan, or --report FILE", file=sys.stderr)
                return EXIT_CONFIG
            scanner = PrismaScanner(PrismaConfig.from_env())
            result = scanner.scan(args.image, save_report_to=args.save_report)
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
