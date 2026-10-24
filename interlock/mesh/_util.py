"""Small helpers the mesh modules share: canonical JSON, hashing, timestamps,
and atomic, size-bounded file I/O. Nothing here is policy."""
from __future__ import annotations

import calendar
import hashlib
import json
import os
import tempfile
import time
from typing import Any

ISO = "%Y-%m-%dT%H:%M:%SZ"


def canonical(obj: Any) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8. Every signature in the
    mesh is over these bytes, so two implementations agree on what was signed."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iso(ts: float) -> str:
    """Seconds since the epoch as ``YYYY-MM-DDTHH:MM:SSZ`` (UTC)."""
    return time.strftime(ISO, time.gmtime(ts))


def from_iso(text: Any) -> float:
    """Parse :func:`iso` output. Raises ``ValueError`` on anything else."""
    if not isinstance(text, str):
        raise ValueError("expected an ISO-8601 UTC timestamp")
    return float(calendar.timegm(time.strptime(text, ISO)))


def atomic_write(path: str, data: bytes, mode: int = 0o644) -> None:
    """Write ``data`` to ``path`` through a rename, so a reader never sees a
    torn file and a crash leaves the previous version in place."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=directory)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_bounded(path: str, max_bytes: int) -> bytes:
    """Read a file of at most ``max_bytes``; raise ``ValueError`` if larger.

    The bound is enforced while reading, not by ``os.stat`` first, so a file
    that grows between the two calls cannot slip past it.
    """
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("{} is larger than {} bytes".format(path, max_bytes))
    return data


def load_json(path: str, max_bytes: int) -> Any:
    return json.loads(read_bounded(path, max_bytes).decode("utf-8"))
