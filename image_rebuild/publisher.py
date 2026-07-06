"""Publish a cleared image to a registry (Docker Hub by default).

Only ever invoked after a clean verify. By default the original tag is
**overwritten** with the rebuilt image (resolved design decision 4); with a
target repo configured, the orchestrator retags first and this module pushes
the target reference instead — useful when the source repo isn't yours (e.g.
fixing `penpotapp/mcp` and publishing to `youruser/penpot-mcp`).

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


def registry_host(image_ref: str) -> str | None:
    """Registry host of an image reference, or None for Docker Hub.

    Docker's own rule: the first path component is a registry host only when
    it contains a "." or ":" or is "localhost" (e.g. `harbor.corp.com/x/y`).
    """
    if "/" not in image_ref:
        return None
    first = image_ref.split("/", 1)[0]
    if "." in first or ":" in first or first == "localhost":
        return None if first in ("docker.io", "index.docker.io") else first
    return None


@dataclass
class RegistryConfig:
    user: str
    token: str

    @classmethod
    def from_env(cls) -> "RegistryConfig":
        """Read REGISTRY_USER/REGISTRY_TOKEN, falling back to DOCKERHUB_*."""
        user = os.environ.get("REGISTRY_USER") or os.environ.get("DOCKERHUB_USER")
        token = os.environ.get("REGISTRY_TOKEN") or os.environ.get("DOCKERHUB_TOKEN")
        if not (user and token):
            missing = [
                n for n in ("DOCKERHUB_USER", "DOCKERHUB_TOKEN")
                if not os.environ.get(n)
            ]
            raise PublishError(
                "Missing registry credentials: " + ", ".join(missing)
                + " (or REGISTRY_USER / REGISTRY_TOKEN)"
            )
        return cls(user=user, token=token)


# Backwards-compatible alias (pre-M6 name).
DockerHubConfig = RegistryConfig


class ImagePublisher(Protocol):
    def login(self) -> None: ...
    def push(self, image: str) -> str | None: ...


# `docker push` prints e.g.  "<tag>: digest: sha256:abc... size: 1234"
_DIGEST_RE = re.compile(r"digest:\s*(sha256:[0-9a-f]+)", re.IGNORECASE)


class DockerPublisher:
    """Logs in to a registry (Docker Hub when `registry` is None) and pushes a tag."""

    def __init__(self, config: RegistryConfig, runner: CommandRunner | None = None,
                 binary: str = "docker", registry: str | None = None):
        self.config = config
        self.runner = runner or SubprocessRunner()
        self.binary = binary
        self.registry = registry

    def login(self) -> None:
        cmd = [self.binary, "login", "--username", self.config.user, "--password-stdin"]
        if self.registry:
            cmd.append(self.registry)
        result = self.runner.run(cmd, input_text=self.config.token)
        if result.returncode != 0:
            raise PublishError(f"docker login failed: {result.stderr.strip()}")

    def push(self, image: str) -> str | None:
        """Push `image`; return the pushed digest if it can be parsed."""
        result = self.runner.run([self.binary, "push", image])
        if result.returncode != 0:
            raise PublishError(f"docker push {image} failed: {result.stderr.strip()}")
        match = _DIGEST_RE.search(result.stdout)
        return match.group(1) if match else None
