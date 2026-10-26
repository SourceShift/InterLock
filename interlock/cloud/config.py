"""Configuration for the cloud control plane, read from ``IL_CLOUD_*``.

The plane binds loopback by default. It may bind publicly (``0.0.0.0``) only
when ``public_url`` is an ``https://`` URL: without TLS termination in front of
it, a public bind would expose sessions and keys in clear text, so
:meth:`CloudConfig.validate` refuses it.

No third-party import belongs in this module: the package must import under
``python3 -I`` with no site-packages installed.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

#: Bind hosts the plane accepts. Arbitrary interface names are refused.
ALLOWED_BIND_HOSTS = ("127.0.0.1", "::1", "localhost", "0.0.0.0")

#: A short secret is brute-forceable, so nothing under this length is accepted.
MIN_SESSION_SECRET_LENGTH = 32

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8787
DEFAULT_LOG_LEVEL = "info"


class ConfigError(ValueError):
    """A cloud configuration value is missing, malformed or unsafe."""


def _default_state_dir() -> Path:
    return Path.home() / ".interlock" / "cloud-plane"


@dataclass(frozen=True)
class CloudConfig:
    """Everything the plane needs to bind, connect and sign sessions.

    Construct it directly in tests and from :meth:`from_env` in production.
    Call :meth:`validate` once at startup: the module-level ASGI app must be
    importable with no DSN so health routes answer before the database exists.
    """

    dsn: str = ""
    bind_host: str = DEFAULT_BIND_HOST
    bind_port: int = DEFAULT_BIND_PORT
    public_url: str = ""
    session_secret: str = ""
    log_level: str = DEFAULT_LOG_LEVEL
    state_dir: Path = field(default_factory=_default_state_dir)

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> "CloudConfig":
        """Build a config from ``IL_CLOUD_*`` variables (or ``environ``)."""
        env = os.environ if environ is None else environ
        port_raw = env.get("IL_CLOUD_PORT")
        if port_raw is None or port_raw == "":
            port = DEFAULT_BIND_PORT
        else:
            try:
                port = int(port_raw)
            except (TypeError, ValueError):
                raise ConfigError(
                    "IL_CLOUD_PORT must be an integer, got {!r}".format(port_raw)
                ) from None
        state_raw = env.get("IL_CLOUD_STATE_DIR")
        state_dir = Path(state_raw).expanduser() if state_raw else _default_state_dir()
        return cls(
            dsn=env.get("IL_CLOUD_DSN", ""),
            bind_host=env.get("IL_CLOUD_BIND", DEFAULT_BIND_HOST),
            bind_port=port,
            public_url=env.get("IL_CLOUD_PUBLIC_URL", ""),
            session_secret=env.get("IL_CLOUD_SESSION_SECRET", ""),
            log_level=env.get("IL_CLOUD_LOG_LEVEL", DEFAULT_LOG_LEVEL),
            state_dir=state_dir,
        )

    def validate(self) -> None:
        """Raise :class:`ConfigError` naming the first unsafe value."""
        if not self.dsn:
            raise ConfigError("IL_CLOUD_DSN is required")
        if self.bind_host not in ALLOWED_BIND_HOSTS:
            raise ConfigError(
                "IL_CLOUD_BIND must be one of {}; got {!r}".format(
                    ", ".join(ALLOWED_BIND_HOSTS), self.bind_host
                )
            )
        if isinstance(self.bind_port, bool) or not isinstance(self.bind_port, int):
            raise ConfigError("IL_CLOUD_PORT must be an integer")
        if not 1 <= self.bind_port <= 65535:
            raise ConfigError(
                "IL_CLOUD_PORT must be between 1 and 65535; got {}".format(
                    self.bind_port
                )
            )
        if len(self.session_secret) < MIN_SESSION_SECRET_LENGTH:
            raise ConfigError(
                "IL_CLOUD_SESSION_SECRET must be at least {} characters".format(
                    MIN_SESSION_SECRET_LENGTH
                )
            )
        if self.bind_host == "0.0.0.0" and not self.public_url.startswith("https://"):
            raise ConfigError(
                "IL_CLOUD_PUBLIC_URL must start with https:// when IL_CLOUD_BIND "
                "is 0.0.0.0: a public bind needs TLS termination in front of it"
            )
