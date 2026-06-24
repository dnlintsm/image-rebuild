# image-rebuild

Local CLI that pulls a Docker image, scans it with **Prisma Cloud Compute**
(`twistcli`), automatically remediates **critical** CVEs by generating and
building a fixed image, verifies the rebuilt image re-scans clean, and pushes it
back to Docker Hub.

**Policy gate:** the pushed image must have **zero critical vulnerabilities**.
The tool refuses to push otherwise. See [`DESIGN.md`](DESIGN.md) for the full
architecture and decisions.

## Status

Milestone **M1 — scan + parse** (current):

- Invoke `twistcli` and normalize its JSON report.
- Or parse an existing report offline with `--report`.
- Print a severity-gated vulnerability summary, flagging unfixable CRITICALs
  (which block the eventual push until an upstream fix ships).

Remediation (planner/generator), the build/verify loop, and publishing land in
later milestones (M2–M5 in `DESIGN.md`).

## Install

```bash
pip install -e .          # or: pip install -e ".[dev]" for tests
```

Requires Python 3.10+ and, for live scans, `twistcli` on your `PATH`.

## Usage

```bash
# Scan a local image via Prisma (needs PRISMA_* env vars + twistcli on PATH)
image-rebuild scan example/app:1.0

# Parse an existing twistcli report offline (no Prisma needed)
image-rebuild scan --report report.json

# Highlight/fail on a different gate severity, and fail CI on findings
image-rebuild scan example/app:1.0 --gate-severity high --fail-on-gate
```

### Credentials (environment only — never committed)

```bash
export PRISMA_CONSOLE_URL="https://<console-host>:<port>"
export PRISMA_USER="..."
export PRISMA_PASSWORD="..."
```

## Develop

```bash
pip install -e ".[dev]"
pytest
```
