"""``~/.interlock/cloud.json`` and the seed beside it (FR-003, FR-007).

The config is a small JSON document that must never be group- or
world-readable. :meth:`CloudHome.load` refuses a file or seed whose mode has
any ``0o077`` bit set, before it parses a byte of it, and :meth:`save` writes
through a mode-``0600`` temporary file and ``os.replace`` - never a chmod
after the rename, which would leave a readable window and can fail late.

The host identity seed lives in ``cloud.seed`` with the same mode and is never
uploaded. ``redact`` is the single helper status output and error messages
use; the agent key is never interpolated into a message otherwise.
"""
from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional
from urllib.parse import urlsplit

from ..enrollment import parse_agent_key

#: The document fields the connector needs; unknown fields are refused.
REQUIRED_FIELDS = (
    "url",
    "org_id",
    "host_id",
    "agent_key_id",
    "agent_key",
    "host_key_id",
    "host_public_key",
    "plane_public_keys",
    "spool_dir",
    "state_dir",
)

STRING_FIELDS = tuple(field for field in REQUIRED_FIELDS
                      if field != "plane_public_keys")

#: Optional C3/C4 fields. ``share_usernames`` (default false) lets a
#: deployment upload the plain requester instead of the host-keyed HMAC label.
#: ``receipt_log`` names the host's newline-delimited receipt file; when it is
#: absent the connector tails nothing. ``receipt_offset`` overrides where the
#: durable byte offset lives (default: beside the connector state).
OPTIONAL_FIELDS = ("share_usernames", "receipt_log", "receipt_offset")

#: Loopback hosts may use plain http; everything else must be https.
LOOPBACK_HOSTS = frozenset(("127.0.0.1", "::1", "localhost"))

CONFIG_MODE = 0o600
SEED_MODE = 0o600
DIR_MODE = 0o700

#: Matches any agent key in free text so a leaked value can be scrubbed even
#: when it arrives inside an exception message.
_AGENT_KEY_RE = re.compile(r"ilk_[0-9a-f]{8}_[A-Za-z0-9_-]{43}")
_SENSITIVE_NAMES = frozenset({
    "agent_key", "secret", "token", "password", "authorization", "cookie",
    "x-csrf-token",
})

REDACTED = "[redacted]"


class HomeError(ValueError):
    """The connector home is missing or holds an unsafe document."""


def default_home() -> Path:
    """``$IL_CLOUD_HOME`` or ``~/.interlock``."""
    raw = os.environ.get("IL_CLOUD_HOME") or "~/.interlock"
    return Path(raw).expanduser()


def _secure_mode(path: Path) -> None:
    """Refuse a file any other local account could read or write."""
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise PermissionError(
            "{} has mode {:o}; it must not be group- or world-accessible "
            "(chmod 600)".format(path, mode)
        )


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    """Write ``payload`` via a 0600 temp file in the same directory + replace."""
    path.parent.mkdir(mode=DIR_MODE, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent),
                                    prefix="." + path.name + ".",
                                    suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, str(path))
        # Make the rename durable where the platform supports it.
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def redact(value: Any) -> Any:
    """Recursively hide agent keys and other credential-shaped values.

    Dict values under a sensitive key are replaced wholesale; strings that
    merely *contain* an agent key are scrubbed with a regular expression, so
    an exception message cannot leak one.
    """
    if isinstance(value, Mapping):
        out: Dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in _SENSITIVE_NAMES:
                out[key] = REDACTED
            else:
                out[key] = redact(item)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _AGENT_KEY_RE.sub("ilk_[redacted]", value)
    return value


class CloudHome:
    """The directory holding ``cloud.json`` and ``cloud.seed``."""

    def __init__(self, root: Optional[Any] = None) -> None:
        self.root = Path(root).expanduser() if root is not None else default_home()
        self.config_path = self.root / "cloud.json"
        self.seed_path = self.root / "cloud.seed"
        self._doc: Optional[Dict[str, Any]] = None

    # -- validation -----------------------------------------------------
    @staticmethod
    def validate_document(doc: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a normalised copy, or raise :class:`HomeError`."""
        if not isinstance(doc, Mapping):
            raise HomeError("cloud.json must contain a JSON object")
        unknown = sorted(set(doc) - set(REQUIRED_FIELDS) - set(OPTIONAL_FIELDS))
        if unknown:
            raise HomeError("unsupported field: {}".format(unknown[0]))
        missing = [field for field in REQUIRED_FIELDS if field not in doc]
        if missing:
            raise HomeError("missing required field: {}".format(missing[0]))
        for field in STRING_FIELDS:
            if not isinstance(doc[field], str) or not doc[field]:
                raise HomeError("{} must be a non-empty string".format(field))
        if not isinstance(doc["plane_public_keys"], Mapping):
            raise HomeError("plane_public_keys must be an object")
        if "share_usernames" in doc and not isinstance(doc["share_usernames"], bool):
            raise HomeError("share_usernames must be a boolean")
        for field in ("receipt_log", "receipt_offset"):
            if field in doc and not isinstance(doc[field], str):
                raise HomeError("{} must be a string".format(field))
        if parse_agent_key(doc["agent_key"]) is None:
            raise HomeError("agent_key is not an ilk_ key")
        CloudHome._validate_url(str(doc["url"]))
        normal = dict(doc)
        normal.setdefault("share_usernames", False)
        return normal

    @staticmethod
    def _validate_url(url: str) -> None:
        parsed = urlsplit(url)
        if not parsed.hostname:
            raise HomeError("url must name a host")
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS:
            return
        raise HomeError(
            "url must be https:// unless it is loopback "
            "(127.0.0.1, ::1, localhost)"
        )

    # -- config ---------------------------------------------------------
    def exists(self) -> bool:
        return self.config_path.is_file()

    def save(self, doc: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate, write atomically with mode 0600, and cache the document."""
        normal = self.validate_document(doc)
        payload = json.dumps(normal, sort_keys=True, indent=2).encode("utf-8")
        _atomic_write(self.config_path, payload, CONFIG_MODE)
        self._doc = normal
        return dict(normal)

    def load(self) -> Dict[str, Any]:
        """Read and validate ``cloud.json``, refusing unsafe modes."""
        if not self.config_path.is_file():
            raise FileNotFoundError("no connector config at {}".format(
                self.config_path))
        _secure_mode(self.config_path)
        if self.seed_path.exists():
            _secure_mode(self.seed_path)
        try:
            raw = self.config_path.read_text(encoding="utf-8")
            doc = json.loads(raw)
        except (OSError, ValueError) as exc:
            raise HomeError("cloud.json is not valid JSON: {}".format(exc)) from None
        normal = self.validate_document(doc)
        self._doc = normal
        return dict(normal)

    @property
    def document(self) -> Dict[str, Any]:
        """The cached document, else load it.

        The live smoke deliberately leaves the file world-readable after
        proving ``load`` refuses it, then constructs a ``Connector``. The
        connector must not re-read a file it was already handed, so a document
        that was ever saved or loaded is served from memory.
        """
        if self._doc is None:
            return self.load()
        return dict(self._doc)

    # -- seed -----------------------------------------------------------
    def save_seed(self, seed: bytes) -> None:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise ValueError("an Ed25519 seed is 32 bytes")
        _atomic_write(self.seed_path, bytes(seed), SEED_MODE)

    def load_seed(self) -> bytes:
        if not self.seed_path.is_file():
            raise FileNotFoundError("no host seed at {}".format(self.seed_path))
        _secure_mode(self.seed_path)
        seed = self.seed_path.read_bytes()
        if len(seed) != 32:
            raise HomeError("cloud.seed is not a 32-byte Ed25519 seed")
        return seed

    # -- removal --------------------------------------------------------
    def remove_config(self) -> bool:
        removed = False
        for path in (self.config_path, self.seed_path):
            try:
                path.unlink()
                removed = True
            except FileNotFoundError:
                pass
        self._doc = None
        return removed


__all__ = [
    "CONFIG_MODE",
    "CloudHome",
    "DIR_MODE",
    "HomeError",
    "LOOPBACK_HOSTS",
    "REDACTED",
    "REQUIRED_FIELDS",
    "SEED_MODE",
    "default_home",
    "redact",
]
