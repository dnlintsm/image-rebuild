"""Publish a cleared image to the registry (Docker Hub).

Only ever invoked after a clean verify. Per the resolved design decisions the
original tag is **overwritten** with the rebuilt image; the orchestrator records
the pre-fix digest so the original can be restored if needed.

Like the builder, this shells out to the `docker` CLI through an injectable
runner so the command construction is unit-testable without a daemon or a real
registry. Credentials come from the environment only.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Protocol

from .builder import CommandRunner, SubprocessRunner


class PublishError(Exception):
    """Raised when login or push fails, or credentials are missing."""


@dataclass
class DockerHubConfig:
    user: str
    token: str

    @classmethod
    def from_env(cls) -> "DockerHubConfig":
        missing = [n for n in ("DOCKERHUB_USER", "DOCKERHUB_TOKEN") if not os.environ.get(n)]
        if missing:
            raise PublishError("Missing Docker Hub credentials: " + ", ".join(missing))
        return cls(user=os.environ["DOCKERHUB_USER"], token=os.environ["DOCKERHUB_TOKEN"])


class ImagePublisher(Protocol):
    def login(self) -> None: ...
    def push(self, image: str) -> str | None: ...


# `docker push` prints e.g.  "<tag>: digest: sha256:abc... size: 1234"
_DIGEST_RE = re.compile(r"digest:\s*(sha256:[0-9a-f]+)", re.IGNORECASE)


class DockerPublisher:
    """Logs in to Docker Hub and pushes an image tag."""

    def __init__(self, config: DockerHubConfig, runner: CommandRunner | None = None,
                 binary: str = "docker"):
        self.config = config
        self.runner = runner or SubprocessRunner()
        self.binary = binary

    def login(self) -> None:
        result = self.runner.run(
            [self.binary, "login", "--username", self.config.user, "--password-stdin"],
            input_text=self.config.token,
        )
        if result.returncode != 0:
            raise PublishError(f"docker login failed: {result.stderr.strip()}")

    def push(self, image: str) -> str | None:
        """Push `image`; return the pushed digest if it can be parsed."""
        result = self.runner.run([self.binary, "push", image])
        if result.returncode != 0:
            raise PublishError(f"docker push {image} failed: {result.stderr.strip()}")
        match = _DIGEST_RE.search(result.stdout)
        return match.group(1) if match else None
