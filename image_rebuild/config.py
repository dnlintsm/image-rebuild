"""Configuration and credential resolution.

Secrets come from the environment only — never from a committed file.
M1 needs just the Prisma Console connection details.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(Exception):
    """Raised when required configuration/credentials are missing."""


@dataclass
class AppConfig:
    """Non-secret settings, loaded from an optional YAML file (see DESIGN.md §5).

    Secrets are never read from here — only from the environment.
    """

    gate_severity: str = "critical"
    max_iterations: int = 3
    package_manager: str | None = None
    base_image_bump: bool = False
    dockerhub_repo: str | None = None
    artifacts_dir: str = "./runs"

    DEFAULT_PATH = "image-rebuild.yaml"

    @classmethod
    def load(cls, path: str | None = None) -> "AppConfig":
        """Load from `path`, else the default file if present, else defaults."""
        chosen = path or (cls.DEFAULT_PATH if os.path.exists(cls.DEFAULT_PATH) else None)
        if not chosen:
            return cls()
        if not os.path.exists(chosen):
            raise ConfigError(f"config file not found: {chosen}")
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover
            raise ConfigError("PyYAML is required to read a config file") from exc
        try:
            data = yaml.safe_load(Path(chosen).read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid config file {chosen}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config file {chosen} must be a mapping")
        registry = data.get("registry") or {}
        return cls(
            gate_severity=data.get("gate_severity", "critical"),
            max_iterations=int(data.get("max_iterations", 3)),
            package_manager=data.get("package_manager"),
            base_image_bump=bool(data.get("base_image_bump", False)),
            dockerhub_repo=registry.get("dockerhub_repo"),
            artifacts_dir=data.get("artifacts_dir", "./runs"),
        )


@dataclass
class PrismaConfig:
    console_url: str
    user: str
    password: str

    @classmethod
    def from_env(cls) -> "PrismaConfig":
        missing = [
            name
            for name in ("PRISMA_CONSOLE_URL", "PRISMA_USER", "PRISMA_PASSWORD")
            if not os.environ.get(name)
        ]
        if missing:
            raise ConfigError(
                "Missing Prisma credentials in environment: " + ", ".join(missing)
            )
        return cls(
            console_url=os.environ["PRISMA_CONSOLE_URL"],
            user=os.environ["PRISMA_USER"],
            password=os.environ["PRISMA_PASSWORD"],
        )
