# image-rebuild — Design Document

A local CLI tool that pulls a Docker image, scans it with **Prisma Cloud
Compute** (`twistcli`), automatically remediates **critical** CVEs by generating
and building a fixed image, verifies the result re-scans clean, and pushes it to
Docker Hub.

**Hard requirement (company policy):** the pushed image must have **zero
CRITICAL vulnerabilities**. The tool refuses to push otherwise.

### Resolved decisions
1. **Unfixable CRITICALs** — **no allowlist**. Company policy does not permit
   exceptions; when a CRITICAL has no upstream fix, the run **blocks** (does not
   push) and reports the blockers as "awaiting upstream fix." Re-run when a fix
   ships.
2. **Distroless / `scratch`** — detect and **fail clearly** (no package manager
   to remediate through).
3. **Base-image bump** — **recommendation-only**, never auto-applied.
4. **Docker Hub tag** — **overwrite the original tag** with the rebuilt image.

---

## 1. Goals & non-goals

### Goals
- One command: `image-rebuild <image:tag>` → pulls, scans, fixes, verifies, pushes.
- Enforce zero-CRITICAL as a gate, not a suggestion. Never push an unclean image.
- Remediate without needing the upstream Dockerfile (rebuild `FROM` the pulled image).
- Idempotent and CI-friendly: deterministic tags, structured logs, meaningful exit codes.
- Auditable: keep every intermediate scan report and the generated Dockerfile.

### Non-goals (v1)
- Fixing HIGH/MEDIUM/LOW (configurable threshold, but default gate is CRITICAL only).
- Rewriting application source code or rebuilding apps from source.
- Managing the Prisma Console / policy configuration.
- Multi-arch builds (single-arch first; buildx is a later extension).

---

## 2. High-level flow

```
        ┌──────────────────────────── orchestrator loop (max N) ───────────────────────────┐
        │                                                                                    │
pull ──▶ scan (twistcli) ──▶ parse ──▶ plan fixes ──▶ generate Dockerfile ──▶ build ──┐      │
        │                                                                              │      │
        │   ◀──────────────────── re-scan rebuilt image ◀───────────────────────────── ┘      │
        │                                                                                    │
        └── 0 critical?  ── yes ──▶ tag ──▶ push ──▶ DONE                                     │
                         ── no, progress made ──▶ loop again                                  │
                         ── no, stuck/unfixable ──▶ FAIL (report remaining CVEs)              │
```

The re-scan is the enforcement point. A fix is only "done" when an independent
scan of the rebuilt image shows `criticalCount == 0`.

---

## 3. Architecture

Python CLI, one module per responsibility so each step is unit-testable and the
scanner/registry can be swapped later.

```
image_rebuild/
├── cli.py            # argparse/typer entrypoint, config loading, exit codes
├── config.py         # config model + env/file/flag merge
├── puller.py         # docker pull
├── scanner.py        # twistcli invocation -> raw JSON report
├── parser.py         # raw report -> normalized Vulnerability list
├── planner.py        # vulnerabilities -> ordered list of FixActions
├── generator.py      # FixActions -> Dockerfile text
├── builder.py        # docker build
├── verifier.py       # re-scan + zero-critical assertion + loop control
├── publisher.py      # docker tag + docker push (Docker Hub)
├── orchestrator.py   # wires the loop together
└── models.py         # dataclasses: Vulnerability, FixAction, ScanResult, RunReport
```

### Docker interaction
Use the **Docker SDK for Python** (`docker` package) for pull/build/tag/push;
shell out to `twistcli` via `subprocess`. Keeping the scanner as a subprocess
makes it trivial to swap Prisma for Trivy/Grype later behind the `scanner`
interface.

---

## 4. Module detail

### 4.1 `scanner.py` — Prisma / twistcli

Prisma Cloud Compute ships `twistcli`. The scan command:

```
twistcli images scan \
    --address   $PRISMA_CONSOLE_URL \
    --user      $PRISMA_USER \
    --password  $PRISMA_PASSWORD \
    --details \
    --output-file <report>.json \
    <image:tag>
```

- `--output-file` writes a structured JSON report (our parse target).
- `--details` includes per-CVE package/fix data.
- Exit code is non-zero when the image violates the configured Prisma policy;
  we do **not** rely on it for the gate — we parse counts ourselves so policy
  config drift can't silently weaken our zero-critical rule.
- Console URL + credentials come from env (`PRISMA_*`), never committed.

> **Confirmed** against the Prisma Cloud Compute docs and a realistic sample
> (`tests/fixtures/twistcli_real_sample.json`): result fields are
> `id/name/distro/distroRelease/digest/collections/vulnerabilities[]`; each
> vulnerability carries `id/status/cvss/vector/description/severity/packageName/
> packageVersion/link/riskFactors/tags`, plus `packageType` and the
> `vulnerabilityDistribution` counts emitted by the real binary (beyond the
> simplified docs schema). The parser reads `packageType` for the ecosystem and
> tolerates `vulnerabilityDistribution` being absent.

### 4.2 `parser.py` — normalize the report

twistcli JSON (typical shape):

```jsonc
{
  "results": [{
    "vulnerabilityDistribution": { "critical": 3, "high": 7, "medium": 0, "low": 1 },
    "vulnerabilities": [{
      "id": "CVE-2024-XXXX",
      "severity": "critical",
      "packageName": "openssl",
      "packageVersion": "3.0.11-1",
      "status": "fixed in 3.0.13-1",   // fix version, when available
      "link": "https://...",
      "cvss": 9.8,
      "type": "os"                     // "os" vs language ecosystem
    }]
  }]
}
```

Normalize each into:

```python
@dataclass
class Vulnerability:
    cve: str
    severity: str          # normalized lower-case
    package: str
    installed: str
    fixed: str | None      # parsed out of `status`; None => no fix available
    ecosystem: str         # os | python | nodejs | go | ...
    cvss: float | None
```

`ScanResult` carries the normalized list plus the distribution counts so the
verifier can gate on `distribution["critical"]` directly.

### 4.3 `planner.py` — map vulnerabilities to fixes

Filter to the configured gate severity (default `critical`), then map each to a
`FixAction`, applied in this priority order (highest leverage first):

1. **Base-image bump** — if many CRITICALs are OS packages, prefer pulling the
   latest patched digest of the same base. (v1: optional/flagged, since it can
   change runtime behavior; off by default, surfaced as a recommendation.)
2. **OS package upgrade** — targeted, pinned to the fixed version:
   - Debian/Ubuntu: `apt-get install -y --only-upgrade <pkg>=<fixed>`
   - Alpine: `apk add --no-cache --upgrade <pkg>=<fixed>`
   - RHEL/UBI: `dnf update -y <pkg>`
   - Fallback when the pinned version isn't in the repo: full `apt-get upgrade`.
3. **Language dependency upgrade** — pip / npm / go / gem to the named fix
   version.
4. **Unfixable** (`fixed is None`) → cannot patch by upgrade. Recorded as a
   **blocker**; the run will not push and reports it as "awaiting upstream fix"
   (§6).

Detecting the OS family / package manager: inspect the image (`docker run --rm
<img> cat /etc/os-release`, probe for `apt`/`apk`/`dnf`). Cached per run.

### 4.4 `generator.py` — Dockerfile emission

Generates a remediation Dockerfile layered on the original image:

```dockerfile
# AUTOGENERATED by image-rebuild — do not edit by hand
FROM <original-image>@<digest>

USER root

# --- OS package remediations (CVE-2024-XXXX, ...) ---
RUN apt-get update && \
    apt-get install -y --only-upgrade \
        openssl=3.0.13-1 \
        libxml2=2.9.14+dfsg-1.3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# --- Language deps (CVE-2024-YYYY) ---
RUN pip install --no-cache-dir --upgrade "requests==2.32.0"

USER <original-user>
```

- Pin to the original image **digest** so reruns are reproducible.
- Restore the original `USER` after privileged upgrade steps.
- Group upgrades per package manager into single layers; annotate each layer
  with the CVEs it addresses for auditability.

### 4.5 `builder.py`
`docker build` the generated Dockerfile. Build context is minimal (just the
Dockerfile). Capture build logs to the run artifacts directory.

### 4.6 `verifier.py` — the gate + loop control
- Re-scan the freshly built image with the same scanner.
- Pass condition: `distribution["critical"] == 0` (or `<= threshold`).
- Loop control: if still > 0 but the count **decreased**, loop again (new CVEs
  can surface after upgrades). If no progress, or only **unfixable** CVEs remain,
  stop and FAIL with a report listing them as "awaiting upstream fix."
- `max_iterations` (default 3) prevents infinite loops.

### 4.7 `publisher.py`
Only invoked after a clean verify.
- Tag: **overwrites the original `<repo>:<tag>`** with the rebuilt image (per
  decision 4). The pre-fix digest is recorded in the run report for rollback.
- `docker login` via `DOCKERHUB_USER` / `DOCKERHUB_TOKEN` (env).
- `docker push`. Print the pushed digest.

---

## 5. Configuration

`image-rebuild.yaml` (overridable by flags; secrets only via env):

```yaml
gate_severity: critical        # critical | high | ...
max_iterations: 3
base_image_bump: false         # opt-in auto rebase
registry:
  dockerhub_repo: mycorp/myapp # original tag is overwritten on push
artifacts_dir: ./runs          # scans + Dockerfiles per run
```

Secrets (env only, never in file/repo):
`PRISMA_CONSOLE_URL`, `PRISMA_USER`, `PRISMA_PASSWORD`,
`DOCKERHUB_USER`, `DOCKERHUB_TOKEN`.

---

## 6. The hard cases (decide policy before coding)

1. **Unfixable CRITICALs (no upstream fix).** Cannot reach zero by upgrading.
   Per decision 1, there is **no allowlist** — the run fails loudly with the
   list of blockers, reported as "awaiting upstream fix." Re-run once a fix
   ships. (A base-image swap that drops the package remains a manual option,
   surfaced as a recommendation.)
2. **Distroless / `scratch` images** — no shell or package manager. OS/lang
   upgrade steps don't apply; only base-image rebase works. Detect and fail
   with a clear message in v1.
3. **Pinned fix version not in repo** — fall back to unpinned upgrade, then
   re-scan to confirm.
4. **Newly surfaced CVEs after upgrade** — handled by the loop, but capped by
   `max_iterations`.

---

## 7. CLI surface

```
image-rebuild scan   <image:tag>            # scan only, print report
image-rebuild fix    <image:tag> [--push]   # full loop; --push gates on clean verify
image-rebuild        <image:tag>            # alias for `fix --push`
  --gate-severity critical
  --max-iterations 3
  --base-image-bump
  --dry-run                                 # generate Dockerfile, don't build/push
  --config image-rebuild.yaml
```

Exit codes: `0` clean & pushed · `1` unfixable CRITICALs remain ·
`2` scanner/build error · `3` config/auth error. (CI-friendly.)

---

## 8. Build order (suggested milestones)

1. **M1 — scan + parse:** `scanner` + `parser` + `models`, `image-rebuild scan`
   prints a normalized table. Validates against a real Prisma report.
2. **M2 — plan + generate (dry run):** `planner` + `generator`, `--dry-run`
   emits the Dockerfile. No build yet.
3. **M3 — build + verify loop:** `builder` + `verifier` + `orchestrator`. Local
   end-to-end to a clean image, no push.
4. **M4 — publish + config + allowlist:** `publisher`, config file, exception
   handling, deterministic tags.
5. **M5 — hardening:** structured logging, artifacts dir, exit codes, tests, CI
   example.

---

## 9. Testing

- Unit: `parser` against captured Prisma JSON fixtures (incl. unfixable,
  multi-ecosystem, empty). `planner`/`generator` snapshot tests on Dockerfile
  output. `verifier` loop-control logic.
- Integration: run the full loop against a deliberately vulnerable public image
  (e.g. an old `python:3.9` tag) using a mock or sandbox scanner.
- Safety: assert push is unreachable in any code path where
  `critical > threshold`.

---

## 10. Open questions

(None blocking.) The `twistcli` JSON schema is confirmed against the Prisma
Cloud Compute docs and a realistic fixture (§4.1); swapping in a report from your
own Console remains a good final sanity check before relying on M3 output.

Resolved: base-image bump is recommendation-only (decision 3); no allowlist for
unfixable CVEs (decision 1); push overwrites the original tag (decision 4);
distroless images fail clearly (decision 2).
