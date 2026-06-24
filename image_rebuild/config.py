"""Configuration and credential resolution.

Secrets come from the environment only — never from a committed file.
M1 needs just the Prisma Console connection details.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


class ConfigError(Exception):
    """Raised when required configuration/credentials are missing."""


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
