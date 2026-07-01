# image-rebuild

Local CLI that pulls a Docker image, scans it with **Prisma Cloud Compute**
(`twistcli`), automatically remediates **critical** CVEs by generating and
building a fixed image, verifies the rebuilt image re-scans clean, and pushes it
back to Docker Hub.

**Policy gate:** the pushed image must have **zero critical vulnerabilities**.
The tool refuses to push otherwise. See [`DESIGN.md`](DESIGN.md) for the full
architecture and decisions.

## Status

Feature-complete (M1–M5). Milestones **M1 — scan + parse**,
**M2 — plan + generate (dry-run)**, **M3 — build + verify loop**,
**M4 — publish + config**, and **M5 — hardening**:

- Invoke `twistcli` and normalize its JSON report (or parse one offline with `--report`).
- Print a severity-gated vulnerability summary, flagging unfixable CRITICALs.
- Build a remediation plan: map each fixable, gate-severity CVE to an OS
  (apt/apk/dnf) or Python (pip) upgrade, dedup per package to the highest
  required fix version, and surface anything needing an app rebuild (`[MANUAL]`)
  or awaiting an upstream fix (`[BLOCKED]`).
- Generate a `FROM`-based remediation Dockerfile (`fix --dry-run`).
- **Run the loop** (`fix <image>`): pull → scan → fix → rebuild → re-scan,
  iterating until the zero-critical gate passes, the count stalls, or only
  unfixable/manual CVEs remain.
- **Publish** (`fix <image> --push`): only after a clean verify, push the
  rebuilt image, **overwriting the original tag**, recording the pre-fix digest
  for rollback.
- **Config file** (`image-rebuild.yaml` / `--config`): gate severity, max
  iterations, package-manager override, etc. CLI flags override it; secrets stay
  in the environment. See [`image-rebuild.example.yaml`](image-rebuild.example.yaml).
- **Run artifacts** (`./runs/<timestamp>_<image>/`): every run persists its scan
  reports (`scan_*.json`), generated Dockerfiles (`Dockerfile.N`), and a
  `run.json` summary for auditing. Disable with `--no-artifacts`; quiet logs with
  `-q`.

## Install

This project uses [uv](https://docs.astral.sh/uv/) for Python environment and
dependency management.

```bash
uv sync                    # create .venv and install the project
uv sync --extra dev        # ...including the test tooling
```

Then run commands through uv (`uv run image-rebuild ...`) or activate the
environment with `source .venv/bin/activate`.

Requires [uv](https://docs.astral.sh/uv/getting-started/installation/),
Python 3.10+ (uv can install it: `uv python install 3.12`), and — for live
scans — `twistcli` on your `PATH`.

## Usage

```bash
# Scan a local image via Prisma (needs PRISMA_* env vars + twistcli on PATH)
image-rebuild scan example/app:1.0

# Parse an existing twistcli report offline (no Prisma needed)
image-rebuild scan --report report.json

# Highlight/fail on a different gate severity, and fail CI on findings
image-rebuild scan example/app:1.0 --gate-severity high --fail-on-gate

# Plan fixes and generate a remediation Dockerfile (no build/push)
image-rebuild fix --report report.json --dry-run -o Dockerfile

# Run the build + verify loop against a live image (needs docker + twistcli)
image-rebuild fix example/app:1.0 --max-iterations 3

# ...and push the cleared image back, overwriting the original tag
image-rebuild fix example/app:1.0 --push --config image-rebuild.yaml
```

### Credentials (environment only — never committed)

```bash
export PRISMA_CONSOLE_URL="https://<console-host>:<port>"
export PRISMA_USER="..."
export PRISMA_PASSWORD="..."

# Only needed for --push:
export DOCKERHUB_USER="..."
export DOCKERHUB_TOKEN="..."
```

## Develop

```bash
uv sync --extra dev
uv run pytest
```

The `uv.lock` file pins the exact dependency versions; CI installs with
`uv sync --locked` so runs are reproducible. After changing dependencies in
`pyproject.toml`, refresh it with `uv lock`.
