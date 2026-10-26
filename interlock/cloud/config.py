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

#: FR-049's session bounds: half an hour idle, twelve hours absolute.
DEFAULT_SESSION_IDLE = 30 * 60
DEFAULT_SESSION_ABSOLUTE = 12 * 60 * 60


class ConfigError(ValueError):
    """A cloud configuration value is missing, malformed or unsafe."""


def _default_state_dir() -> Path:
    return Path.home() / ".interlock" / "cloud-plane"


def _int_env(env: Mapping[str, str], name: str, default: int) -> int:
    """Read an optional integer, naming the variable when it is malformed."""
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ConfigError(
            "{} must be an integer, got {!r}".format(name, raw)
        ) from None


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
    # -- identity (C1) ---------------------------------------------------
    # Optional: the OIDC provider the plane trusts. An unset issuer means
    # no interactive login is configured, which is how the health routes and
    # the migration runner keep working on a bare interpreter.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    #: Slug of the org humans land in when a login has no per-org issuer.
    oidc_org_slug: str = ""
    #: Session lifetime bounds from FR-049: 30 minute idle, 12 hour absolute.
    session_idle_seconds: int = DEFAULT_SESSION_IDLE
    session_absolute_seconds: int = DEFAULT_SESSION_ABSOLUTE
    # -- C3: preview encryption and grant signing -----------------------
    #: Hex or base64 key for the per-org preview envelope key. Empty means
    #: preview storage is not configured; the routes that need it fail closed.
    preview_kek: str = ""
    #: The hex 32-byte Ed25519 approval seed. Never stored in the database,
    #: never logged; a self-hosted plane supplies it as a 0600 file.
    approval_key_file: str = ""

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
            oidc_issuer=env.get("IL_CLOUD_OIDC_ISSUER", ""),
            oidc_client_id=env.get("IL_CLOUD_OIDC_CLIENT_ID", ""),
            oidc_client_secret=env.get("IL_CLOUD_OIDC_CLIENT_SECRET", ""),
            oidc_redirect_uri=env.get("IL_CLOUD_OIDC_REDIRECT_URI", ""),
            oidc_org_slug=env.get("IL_CLOUD_OIDC_ORG_SLUG", ""),
            session_idle_seconds=_int_env(
                env, "IL_CLOUD_SESSION_IDLE", DEFAULT_SESSION_IDLE
            ),
            session_absolute_seconds=_int_env(
                env, "IL_CLOUD_SESSION_ABSOLUTE", DEFAULT_SESSION_ABSOLUTE
            ),
            preview_kek=env.get("IL_CLOUD_PREVIEW_KEK", ""),
            approval_key_file=env.get("IL_CLOUD_APPROVAL_KEY_FILE", ""),
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
