"""The installed detector set as one identifier.

A mesh report is counted only when it came from detectors the commons
published, unmodified. The way to say "unmodified" without shipping code is a
hash: the sorted file names and contents of every module in
``interlock.detectors``, plus the interlock version. Two deployments with the
same release and no local edits produce the same ``catalog_id``; a patched
detector produces a different one, and the consensus engine ignores reports
from catalogs it does not know. The same idea keeps a community blocklist
honest in CrowdSec, where only unmodified hub scenarios count toward consensus.

The id is computed once per process and stamped onto receipts as ``catalog``
once :func:`interlock.receipt.set_catalog_id` has been called (the subscriber
does that on first use), so a report built from receipts can cite it.
"""
from __future__ import annotations

import hashlib
import os
import threading
from typing import List, Optional, Tuple

__all__ = ["catalog_id", "catalog_entries", "CATALOG_ID_LENGTH"]

CATALOG_ID_LENGTH = 16
_lock = threading.Lock()
_cached: Optional[str] = None


def catalog_entries() -> List[Tuple[str, str]]:
    """``(module file name, sha256 of its bytes)`` for every detector module."""
    from .. import detectors

    directory = os.path.dirname(os.path.abspath(detectors.__file__))
    entries: List[Tuple[str, str]] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(directory, name), "rb") as fh:
            entries.append((name, hashlib.sha256(fh.read()).hexdigest()))
    return entries


def catalog_id(refresh: bool = False) -> str:
    """The detector catalog's identifier: 16 hex characters."""
    global _cached
    with _lock:
        if _cached is not None and not refresh:
            return _cached
        from .. import __version__
        digest = hashlib.sha256()
        digest.update(("interlock " + __version__).encode("utf-8"))
        for name, file_hash in catalog_entries():
            digest.update(b"\0" + name.encode("utf-8") + b"\0" + file_hash.encode("ascii"))
        _cached = digest.hexdigest()[:CATALOG_ID_LENGTH]
        return _cached
