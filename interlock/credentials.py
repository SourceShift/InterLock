"""Placeholder credentials: the agent names a secret, the guard supplies it (R20).

Agents need credentials to call tools, so credentials end up in prompts,
context windows, tool arguments and logs, and redaction detectors clean up
afterwards. This module keeps the secret out of the model's reach altogether:

- The agent writes a **placeholder** where the secret goes:
  ``{{secret:stripe_live}}``. It can list the ids it may use (with labels, never
  values) through :meth:`SecretStore.catalog`, which you can expose as a tool.
- Policy rules see the placeholder, never the value, so they can reason about
  *which* secret a call uses.
- After the policy decision is final, at the enforcement boundary, each
  placeholder is replaced with the real value - but only if that secret is
  allowed for this action (and, when it names hosts, only if every URL in the
  call goes to one of them). Anything else is blocked.
- On the way back, the real value is scrubbed from the tool's result before any
  result rule or the agent sees it.

Receipts digest the arguments as the policy saw them (placeholders), and a
``credentials`` receipt records which secret ids each call used - never values.

Substitution happens after evaluation by design: a rewrite rule would have to
be the very last rule, and any rule placed after it (or a logging hook) would
see the real value. Nothing here touches the network; values come from
environment variables, files, a literal, or a callable you supply (a keychain
lookup, say).

The coding-agent hook adapters do not use this: a value substituted into a
Claude Code tool input becomes part of the agent's own transcript.
"""
from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .enforce import Blocked, Decision, Verdict
from .event import SensorEvent

#: ``{{secret:<id>}}``, spaces allowed inside the braces.
PLACEHOLDER = re.compile(r"\{\{\s*secret:([A-Za-z0-9_.:-]{1,128})\s*\}\}")
POLICY_ID = "credentials"
_URL_KEYS = ("url", "endpoint", "uri", "base_url", "host")


def placeholder(secret_id: str) -> str:
    """The placeholder text for ``secret_id``."""
    return "{{secret:%s}}" % secret_id


@dataclass(frozen=True)
class Secret:
    """One credential the guard may supply. ``actions`` and ``hosts`` bound
    where it may go; ``label`` and ``tags`` are non-secret descriptions."""

    id: str
    actions: FrozenSet[str]
    hosts: FrozenSet[str] = frozenset()
    label: str = ""
    tags: Tuple[str, ...] = ()
    source: Callable[[], str] = field(default=lambda: "", repr=False, compare=False)


class SecretStore:
    """The secrets this process can substitute. Values are read on first use."""

    def __init__(self) -> None:
        self._secrets: Dict[str, Secret] = {}
        self._resolved: Dict[str, str] = {}
        self._lock = threading.Lock()

    def add(self, secret_id: str, *, actions: Iterable[str], value: Optional[str] = None,
            env: Optional[str] = None, file: Optional[str] = None,
            getter: Optional[Callable[[], str]] = None, hosts: Iterable[str] = (),
            label: str = "", tags: Iterable[str] = ()) -> "SecretStore":
        """Register a secret from exactly one source: ``value``, ``env``,
        ``file`` or ``getter``. ``actions`` must be non-empty."""
        if not PLACEHOLDER.fullmatch(placeholder(secret_id)):
            raise ValueError("secret ids are 1-128 characters of [A-Za-z0-9_.:-]")
        sources = [s for s in (value, env, file, getter) if s is not None]
        if len(sources) != 1:
            raise ValueError("give exactly one of value=, env=, file=, getter=")
        allowed = frozenset(actions)
        if not allowed:
            raise ValueError("a secret needs at least one allowed action")
        if value is not None:
            source: Callable[[], str] = lambda v=value: v
        elif env is not None:
            source = lambda name=env: _from_env(name)
        elif file is not None:
            source = lambda path=file: _from_file(path)
        else:
            source = getter  # type: ignore[assignment]
        with self._lock:
            self._secrets[secret_id] = Secret(secret_id, allowed, frozenset(h.lower() for h in hosts),
                                              label, tuple(tags), source)
            self._resolved.pop(secret_id, None)
        return self

    def catalog(self) -> List[Dict[str, Any]]:
        """What an agent may know: ids, labels, tags and allowed actions."""
        with self._lock:
            return [{"id": s.id, "label": s.label, "tags": list(s.tags),
                     "actions": sorted(s.actions), "hosts": sorted(s.hosts)}
                    for s in sorted(self._secrets.values(), key=lambda s: s.id)]

    def get(self, secret_id: str) -> Optional[Secret]:
        with self._lock:
            return self._secrets.get(secret_id)

    def _value(self, secret: Secret) -> str:
        with self._lock:
            cached = self._resolved.get(secret.id)
        if cached is not None:
            return cached
        value = secret.source()
        if not isinstance(value, str) or not value:
            raise LookupError("secret {!r} has no value".format(secret.id))
        with self._lock:
            self._resolved[secret.id] = value
        return value

    def known_values(self) -> List[Tuple[str, str]]:
        """(id, value) for every secret resolved so far - for scrubbing."""
        with self._lock:
            return sorted(self._resolved.items(), key=lambda kv: -len(kv[1]))


def _from_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise LookupError("environment variable {} is not set".format(name))
    return value


def _from_file(path: str) -> str:
    with open(os.path.expanduser(path), "r", encoding="utf-8") as fh:
        return fh.read().strip()


_store: Optional[SecretStore] = None


def install_store(store: Optional[SecretStore]) -> None:
    """Install (or with None, remove) the process secret store."""
    global _store
    _store = store


def get_store() -> Optional[SecretStore]:
    return _store


# --- the enforcement-boundary steps ----------------------------------------------


def used_ids(value: Any, depth: int = 0) -> List[str]:
    """Secret ids named by placeholders anywhere in ``value``."""
    found: List[str] = []
    if isinstance(value, str):
        found.extend(m.group(1) for m in PLACEHOLDER.finditer(value))
    elif depth < 8 and isinstance(value, dict):
        for item in value.values():
            found.extend(used_ids(item, depth + 1))
    elif depth < 8 and isinstance(value, (list, tuple)):
        for item in value:
            found.extend(used_ids(item, depth + 1))
    return found


def _urls(args: Dict[str, Any]) -> List[str]:
    urls = []
    for key, value in args.items():
        if isinstance(value, str) and (key in _URL_KEYS or value.startswith(("http://", "https://"))):
            urls.append(value)
    return urls


def check(event: SensorEvent, ids: List[str]) -> Optional[Decision]:
    """A BLOCK if any placeholder in this call may not be filled, else None."""
    store = get_store()
    for secret_id in ids:
        secret = store.get(secret_id) if store is not None else None
        if secret is None:
            return Decision.block("unknown secret {!r}".format(secret_id), POLICY_ID)
        if event.action not in secret.actions:
            return Decision.block("secret {!r} is not allowed for action {!r}".format(
                secret_id, event.action), POLICY_ID)
        if secret.hosts:
            for url in _urls(event.args if isinstance(event.args, dict) else {}):
                host = (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
                if host not in secret.hosts:
                    return Decision.block("secret {!r} may not be sent to {!r}".format(
                        secret_id, host), POLICY_ID)
    return None


def fill(value: Any, depth: int = 0) -> Any:
    """``value`` with every placeholder replaced by its secret. Call only
    after :func:`check` passed."""
    store = get_store()
    if store is None:
        return value
    if isinstance(value, str):
        def swap(match: "re.Match[str]") -> str:
            secret = store.get(match.group(1))
            if secret is None:  # check() refuses this first; never leak a partial
                raise LookupError(match.group(1))
            return store._value(secret)
        return PLACEHOLDER.sub(swap, value)
    if depth < 8 and isinstance(value, dict):
        return {k: fill(v, depth + 1) for k, v in value.items()}
    if depth < 8 and isinstance(value, list):
        return [fill(v, depth + 1) for v in value]
    if depth < 8 and isinstance(value, tuple):
        return tuple(fill(v, depth + 1) for v in value)
    return value


def scrub(value: Any, depth: int = 0) -> Any:
    """``value`` with every resolved secret replaced by its placeholder."""
    store = get_store()
    if store is None:
        return value
    pairs = store.known_values()
    if not pairs:
        return value
    if isinstance(value, str):
        for secret_id, secret in pairs:
            if secret in value:
                value = value.replace(secret, placeholder(secret_id))
        return value
    if depth < 8 and isinstance(value, dict):
        return {k: scrub(v, depth + 1) for k, v in value.items()}
    if depth < 8 and isinstance(value, list):
        return [scrub(v, depth + 1) for v in value]
    if depth < 8 and isinstance(value, tuple):
        return tuple(scrub(v, depth + 1) for v in value)
    return value


def substitute_call(event: SensorEvent, args: Any, *, enforcement: str = "blocking") -> Any:
    """The boundary step for a call: check, record, fill. Raises
    :class:`Blocked` for a placeholder that may not be filled (in monitor mode
    the placeholder is left unfilled and the refusal recorded as observed)."""
    if get_store() is None:
        return args
    ids = sorted(set(used_ids(args)))
    if not ids:
        return args
    from .receipt import emit_receipt

    refused = check(event, ids)
    if refused is not None:
        if enforcement == "monitor":
            emit_receipt(event, refused, observed=True)
            return args
        emit_receipt(event, refused)
        raise Blocked(refused, event.action)
    try:
        filled = fill(args)
    except LookupError as exc:
        refused = Decision.block("secret {} could not be read: {}".format(
            ", ".join(ids), type(exc).__name__), POLICY_ID)
        emit_receipt(event, refused)
        raise Blocked(refused, event.action)
    emit_receipt(event, Decision(Verdict.ALLOW, "filled secret(s): {}".format(", ".join(ids)),
                                 POLICY_ID))
    return filled
