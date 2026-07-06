# image-rebuild

CLI that pulls a Docker image, scans it (**Prisma Cloud Compute** via
`twistcli`, or **Trivy**), automatically remediates **critical** CVEs by
generating and building a fixed image, verifies the rebuilt image re-scans
clean, and pushes it to a registry.

**Policy gate:** the pushed image must have **zero critical vulnerabilities**.
The tool refuses to push otherwise. See [`DESIGN.md`](DESIGN.md) for the full
architecture and decisions.

## Status

Feature-complete (M1–M5) plus cloud/CI support (M6). Milestones **M1 — scan +
parse**, **M2 — plan + generate (dry-run)**, **M3 — build + verify loop**,
**M4 — publish + config**, **M5 — hardening**, and **M6 — cloud**:

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
- **Publish** (`fix <image> --push`): only after a clean verify. By default the
  original tag is overwritten (recording the pre-fix digest for rollback); with
  `--target-repo` the fixed image is pushed to a repo you own instead — required
  when the source image isn't yours (e.g. fixing `penpotapp/mcp` and publishing
  `youruser/penpot-mcp`).
- **Scanner backends** (`--scanner prisma|trivy`): Prisma/twistcli needs a
  licensed Console reachable from the runner; [Trivy](https://trivy.dev) is
  free and self-contained — use it when running outside the company network
  (e.g. GitHub Actions).
- **Config file** (`image-rebuild.yaml` / `--config`): gate severity, max
  iterations, scanner, target repo, etc. CLI flags override it; secrets stay
  in the environment. See [`image-rebuild.example.yaml`](image-rebuild.example.yaml).
- **Run artifacts** (`./runs/<timestamp>_<image>/`): every run persists its scan
  reports (`scan_*.json`), generated Dockerfiles (`Dockerfile.N`), and a
  `run.json` summary for auditing. Disable with `--no-artifacts`; quiet logs with
  `-q`.
- **Cloud runs** ([`.github/workflows/rebuild-image.yml`](.github/workflows/rebuild-image.yml)):
  run the whole loop on a GitHub-hosted runner and publish the fixed image to
  Docker Hub, where an internal registry (e.g. Harbor proxy-cache) can pull it.

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
scans — `twistcli` or [`trivy`](https://trivy.dev/latest/getting-started/installation/)
on your `PATH`.

## Usage

```bash
# Scan a local image via Prisma (needs PRISMA_* env vars + twistcli on PATH)
image-rebuild scan example/app:1.0

# ...or via Trivy (no console, no license)
image-rebuild scan example/app:1.0 --scanner trivy

# Parse an existing report offline (twistcli or Trivy JSON, auto-detected)
image-rebuild scan --report report.json

# Highlight/fail on a different gate severity, and fail CI on findings
image-rebuild scan example/app:1.0 --gate-severity high --fail-on-gate

# Plan fixes and generate a remediation Dockerfile (no build/push)
image-rebuild fix --report report.json --dry-run -o Dockerfile

# Run the build + verify loop against a live image (needs docker + a scanner)
image-rebuild fix example/app:1.0 --max-iterations 3

# ...and push the cleared image back, overwriting the original tag
image-rebuild fix example/app:1.0 --push --config image-rebuild.yaml

# Fix a third-party image and publish it to a repo you own
image-rebuild fix penpotapp/mcp:latest --scanner trivy \
    --target-repo youruser/penpot-mcp --push
```

### Credentials (environment only — never committed)

```bash
# Only for --scanner prisma:
export PRISMA_CONSOLE_URL="https://<console-host>:<port>"
export PRISMA_USER="..."
export PRISMA_PASSWORD="..."

# Only needed for --push (REGISTRY_USER/REGISTRY_TOKEN also accepted,
# e.g. for Harbor or another private registry):
export DOCKERHUB_USER="..."
export DOCKERHUB_TOKEN="..."
```

## Run it in the cloud (GitHub Actions)

The [`Rebuild image`](.github/workflows/rebuild-image.yml) workflow runs the
full loop on a GitHub-hosted runner — no local Docker or scanner install
needed. Trigger it from the Actions tab (`workflow_dispatch`) with:

- **image** — the source image, e.g. `penpotapp/mcp:latest`
- **target_repo** — the repo you own to publish the fixed image to,
  e.g. `youruser/penpot-mcp` (leave empty only when you can push to the
  source repo itself)
- **scanner** — `trivy` (default; works anywhere) or `prisma` (only if your
  Console is reachable from the internet)

Set the `DOCKERHUB_USER` / `DOCKERHUB_TOKEN` repository secrets (and the
`PRISMA_*` secrets if using Prisma). Each run uploads its `runs/` audit trail
(scan reports, generated Dockerfiles, `run.json`) as a workflow artifact and
writes a summary to the job page. A registry that can proxy public registries
(e.g. Harbor with a Docker Hub proxy project) can then pull the fixed image
from your repo into the internal network.

## Develop

```bash
uv sync --extra dev
uv run pytest
```

The `uv.lock` file pins the exact dependency versions; CI installs with
`uv sync --locked` so runs are reproducible. After changing dependencies in
`pyproject.toml`, refresh it with `uv lock`.
