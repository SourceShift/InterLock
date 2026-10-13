"""Where the hook adapters keep their state, and how a hook builds its engine.

``~/.interlock/`` (mode 0700) holds ``policy.json`` (by default just
``{"extends": "builtin:coding-agent"}``), ``receipts.jsonl`` and its MAC key
``receipts.key``, and ``trusted.json`` (project overlays you approved). The
coding-agent pack locks agent writes to this directory.
"""
from __future__ import annotations

import json
import os
import secrets
from typing import Any, Optional, Tuple

DEFAULT_POLICY = {"version": 1, "extends": "builtin:coding-agent"}


def home() -> str:
    return os.path.join(os.path.expanduser("~"), ".interlock")


def policy_path() -> str:
    return os.path.join(home(), "policy.json")


def receipts_paths() -> Tuple[str, str]:
    return os.path.join(home(), "receipts.jsonl"), os.path.join(home(), "receipts.key")


def ensure_home() -> str:
    """Create ``~/.interlock`` (0700), a default policy and a receipt key, if
    missing. Never overwrites. Returns the directory."""
    directory = home()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    path = policy_path()
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_POLICY, fh, indent=2)
            fh.write("\n")
    _, key = receipts_paths()
    if not os.path.exists(key):
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32) + "\n")
    return directory


def load_engine(*, policy: Optional[str] = None, rules: Optional[str] = None,
                sidecar: Optional[str] = None, cwd: Optional[str] = None,
                overlay: bool = True) -> Any:
    """The engine one hook invocation decides with.

    ``sidecar`` wins (the daemon owns the policy), then ``rules`` (a Python
    module), then ``policy`` (a file), then ``~/.interlock/policy.json``, then
    the built-in coding-agent pack. A trusted project overlay found from
    ``cwd`` is applied to file and built-in policies.
    """
    if sidecar:
        from ..sidecar.client import RemoteEngine
        return RemoteEngine(sidecar)
    if rules:
        from ..sidecar.rules import load_rules
        return load_rules(rules)
    from ..policy.declarative import _record_overlay, _trusted_overlay, load_policy, load_policy_file
    from ..policy.trust import TrustStore, find_overlay

    overlays = []
    found = find_overlay(cwd) if (overlay and cwd) else None
    if found:
        overlays.append(found)
    path = policy or (policy_path() if os.path.exists(policy_path()) else None)
    trust = TrustStore()
    if path:
        return load_policy_file(path, overlays=overlays, trust=trust)
    accepted = []
    for overlay_path in overlays:
        status, doc = _trusted_overlay(overlay_path, trust)
        if doc is None:
            _record_overlay(overlay_path, status)
        else:
            accepted.append((overlay_path, doc))
    engine = load_policy(DEFAULT_POLICY, source="builtin:coding-agent", overlays=accepted)
    for name, status in engine.overlays:
        _record_overlay(name, status)
    return engine
