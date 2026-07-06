"""Persist a per-run audit trail: scan reports, generated Dockerfiles, summary.

Each run gets a timestamped directory under the artifacts dir (default ./runs)
containing the normalized scan results, every generated Dockerfile, and a
`run.json` summary. The orchestrator talks to an `ArtifactSink`; production wires
`RunArtifacts` (writes to disk), tests use `NullArtifacts` (no-op) or a temp dir.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol

from .models import ScanResult

if TYPE_CHECKING:
    from .orchestrator import RunOutcome


class ArtifactSink(Protocol):
    def record_scan(self, label: str, result: ScanResult) -> None: ...
    def record_dockerfile(self, iteration: int, text: str) -> None: ...
    def finalize(self, outcome: "RunOutcome") -> str | None: ...


class NullArtifacts:
    """No-op sink (default when artifacts are disabled)."""

    def record_scan(self, label: str, result: ScanResult) -> None:
        pass

    def record_dockerfile(self, iteration: int, text: str) -> None:
        pass

    def finalize(self, outcome: "RunOutcome") -> str | None:
        return None


def _slug(image: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", image)


class RunArtifacts:
    """Writes a run's scan reports, Dockerfiles, and summary to disk."""

    def __init__(self, base_dir: str, image: str,
                 clock: Callable[[], datetime] | None = None):
        now = (clock or (lambda: datetime.now(timezone.utc)))()
        self.dir = Path(base_dir) / f"{now.strftime('%Y%m%dT%H%M%SZ')}_{_slug(image)}"
        self.dir.mkdir(parents=True, exist_ok=True)

    def record_scan(self, label: str, result: ScanResult) -> None:
        path = self.dir / f"scan_{label}.json"
        path.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")

    def record_dockerfile(self, iteration: int, text: str) -> None:
        (self.dir / f"Dockerfile.{iteration}").write_text(text, encoding="utf-8")

    def finalize(self, outcome: "RunOutcome") -> str | None:
        summary = {
            "status": outcome.status,
            "image": outcome.image,
            "iterations": outcome.iterations,
            "message": outcome.message,
            "final_critical_count": outcome.final_result.critical_count,
            "blockers": [v.cve for v in outcome.blockers],
            "unsupported": [v.cve for v in outcome.unsupported],
            "original_digest": outcome.original_digest,
            "pushed": outcome.pushed,
            "pushed_ref": outcome.pushed_ref,
            "pushed_digest": outcome.pushed_digest,
        }
        (self.dir / "run.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return str(self.dir)
