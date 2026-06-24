"""Scanner interface and the Prisma Cloud Compute (twistcli) implementation.

The scanner is intentionally a thin subprocess wrapper so it can be swapped for
Trivy/Grype later behind the same `scan()` contract.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import PrismaConfig
from .models import ScanResult
from .parser import parse_report


class ScannerError(Exception):
    """Raised when the scanner cannot be run or its output cannot be read."""


class PrismaScanner:
    """Runs `twistcli images scan` and returns a normalized ScanResult."""

    def __init__(self, config: PrismaConfig, binary: str = "twistcli"):
        self.config = config
        self.binary = binary

    def _ensure_binary(self) -> None:
        if shutil.which(self.binary) is None:
            raise ScannerError(
                f"'{self.binary}' not found on PATH. Install twistcli from your "
                "Prisma Cloud Console (Manage > System > Utilities)."
            )

    def scan(self, image: str, save_report_to: str | Path | None = None) -> ScanResult:
        """Pull-free scan of an already-present local image; returns ScanResult.

        If `save_report_to` is given, the raw twistcli JSON is also written there
        for auditing; otherwise a temp file is used and discarded.
        """
        self._ensure_binary()

        report_path = Path(save_report_to) if save_report_to else Path(
            tempfile.mkstemp(prefix="twistcli-", suffix=".json")[1]
        )

        cmd = [
            self.binary, "images", "scan",
            "--address", self.config.console_url,
            "--user", self.config.user,
            "--password", self.config.password,
            "--details",
            "--output-file", str(report_path),
            image,
        ]
        try:
            # twistcli returns non-zero when the image fails Console policy; that
            # is expected here — we gate on parsed counts, not the exit code.
            subprocess.run(cmd, capture_output=True, text=True, check=False)
        except OSError as exc:  # pragma: no cover - environment dependent
            raise ScannerError(f"Failed to execute {self.binary}: {exc}") from exc

        if not report_path.exists():
            raise ScannerError(
                "twistcli did not produce a report. Check Console URL and "
                "credentials (PRISMA_CONSOLE_URL / PRISMA_USER / PRISMA_PASSWORD)."
            )
        try:
            raw = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScannerError(f"twistcli report is not valid JSON: {exc}") from exc

        return parse_report(raw, image_fallback=image)
