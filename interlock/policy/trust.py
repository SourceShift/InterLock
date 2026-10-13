"""Trust for project policy overlays, direnv-style, keyed on content.

A repository can ship ``.interlock/policy.json`` to adjust the policy for work
inside it. That file is written by whoever controls the repository - possibly
the agent itself - so it is ignored until a human trusts it:

    interlock trust add          # shows what the overlay adds, then records it
    interlock trust list         # ok / CHANGED / MISSING for every entry
    interlock trust remove

Trust is recorded as ``{absolute path: sha256 of the file's bytes}``. Editing
the file after trusting it changes the hash and revokes trust until it is
approved again, so an innocent overlay cannot be trusted and then swapped for a
hostile one. Overlays can only tighten a policy or widen lists the base marks
widenable (see :mod:`interlock.policy.declarative`), so even a trusted overlay
cannot switch protection off.

The trust file must be unwritable by the agent. The coding-agent policy pack
locks writes under ``~/.interlock`` for exactly this reason; anywhere else,
keep the file outside what the agent can write.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from typing import Dict, List, Optional, Tuple

#: Overlay file names looked for in ``.interlock/``, in order.
OVERLAY_NAMES = ("policy.json", "policy.yaml", "policy.yml")


def default_trust_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock", "trusted.json")


def file_digest(path: str) -> str:
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


class TrustStore:
    """The set of trusted overlays: path -> content hash, in a JSON file."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or default_trust_path()

    def _load(self) -> Dict[str, Dict[str, object]]:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            return {}  # unreadable trust is no trust
        entries = data.get("trusted", {}) if isinstance(data, dict) else {}
        return {k: v for k, v in entries.items()
                if isinstance(k, str) and isinstance(v, dict) and isinstance(v.get("sha256"), str)}

    def _save(self, entries: Dict[str, Dict[str, object]]) -> None:
        directory = os.path.dirname(self.path)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".trusted-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "trusted": entries}, fh, indent=2, sort_keys=True)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def status(self, path: str, digest: Optional[str] = None) -> str:
        """``ok``, ``untrusted``, ``changed`` (edited since trusted) or ``missing``."""
        path = os.path.abspath(path)
        entry = self._load().get(path)
        if entry is None:
            return "untrusted"
        if not os.path.exists(path):
            return "missing"
        current = digest if digest is not None else file_digest(path)
        return "ok" if entry["sha256"] == current else "changed"

    def add(self, path: str) -> str:
        """Trust the file's current content; return its hash."""
        path = os.path.abspath(path)
        digest = file_digest(path)
        entries = self._load()
        entries[path] = {"sha256": digest, "trusted_at": time.time()}
        self._save(entries)
        return digest

    def remove(self, path: str) -> bool:
        path = os.path.abspath(path)
        entries = self._load()
        if path not in entries:
            return False
        del entries[path]
        self._save(entries)
        return True

    def entries(self) -> List[Tuple[str, str]]:
        """Every trusted path with its status, sorted by path."""
        return [(p, self.status(p)) for p in sorted(self._load())]


def find_overlay(start: str) -> Optional[str]:
    """The nearest ``.interlock/policy.*`` from ``start`` upward.

    The walk stops at the enclosing git root (a directory holding ``.git``) and
    never treats the home directory's ``~/.interlock`` - the global policy - as
    an overlay.
    """
    home_config = os.path.join(os.path.expanduser("~"), ".interlock")
    current = os.path.abspath(start)
    while True:
        candidate_dir = os.path.join(current, ".interlock")
        if os.path.abspath(candidate_dir) != os.path.abspath(home_config):
            for name in OVERLAY_NAMES:
                candidate = os.path.join(candidate_dir, name)
                if os.path.isfile(candidate):
                    return candidate
        if os.path.exists(os.path.join(current, ".git")):
            return None
        parent = os.path.dirname(current)
        if parent == current:
            return None
        current = parent
