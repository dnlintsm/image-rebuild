"""Docker build/pull/inspect via the `docker` CLI.

Shelled out (like the scanner) rather than using the Docker SDK, so there is no
hard Python dependency and the command construction stays unit-testable through
an injectable runner. A real daemon is only needed at execution time.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class BuildError(Exception):
    """Raised when a docker pull/build/inspect command fails."""


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    def run(self, cmd: list[str], cwd: str | None = None) -> RunResult: ...


class SubprocessRunner:
    """Default runner: executes the command with subprocess."""

    def run(self, cmd: list[str], cwd: str | None = None) -> RunResult:
        try:
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
        except OSError as exc:  # pragma: no cover - environment dependent
            raise BuildError(f"failed to execute {' '.join(cmd[:2])}: {exc}") from exc
        return RunResult(proc.returncode, proc.stdout, proc.stderr)


class ImageBuilder(Protocol):
    def pull(self, image: str) -> None: ...
    def build(self, dockerfile_text: str, tag: str) -> str: ...
    def inspect_user(self, image: str) -> str | None: ...


class DockerBuilder:
    """Thin `docker` CLI wrapper used by the orchestrator."""

    def __init__(self, runner: CommandRunner | None = None, binary: str = "docker"):
        self.runner = runner or SubprocessRunner()
        self.binary = binary

    def pull(self, image: str) -> None:
        result = self.runner.run([self.binary, "pull", image])
        if result.returncode != 0:
            raise BuildError(f"docker pull {image} failed: {result.stderr.strip()}")

    def build(self, dockerfile_text: str, tag: str) -> str:
        """Build `dockerfile_text` (a FROM-based remediation Dockerfile) as `tag`.

        Uses a minimal temp build context — the remediation Dockerfile only does
        FROM + RUN (no COPY), so no project files are needed.
        """
        with tempfile.TemporaryDirectory(prefix="image-rebuild-ctx-") as ctx:
            (Path(ctx) / "Dockerfile").write_text(dockerfile_text, encoding="utf-8")
            result = self.runner.run([self.binary, "build", "-t", tag, ctx], cwd=ctx)
        if result.returncode != 0:
            raise BuildError(f"docker build for {tag} failed: {result.stderr.strip()}")
        return tag

    def inspect_user(self, image: str) -> str | None:
        """Return the image's configured USER, or None if root/unset."""
        result = self.runner.run(
            [self.binary, "inspect", "--format", "{{.Config.User}}", image]
        )
        if result.returncode != 0:
            return None
        user = result.stdout.strip()
        return user or None
