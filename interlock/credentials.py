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

import copy
import dataclasses
import os
import re
import threading
import types
from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from ._url import destination_host
from .enforce import Blocked, Decision, Verdict
from .event import SensorEvent

#: ``{{secret:<id>}}``, spaces allowed inside the braces.
PLACEHOLDER = re.compile(r"\{\{\s*secret:([A-Za-z0-9_.:-]{1,128})\s*\}\}")
POLICY_ID = "credentials"
_URL_KEYS = ("url", "endpoint", "uri", "base_url", "host")
_URL_KEY_SET = frozenset(key.lower() for key in _URL_KEYS)
#: The depth a destination walk follows before it stops looking.
_MAX_DESTINATION_DEPTH = 8
# Tokens in a free-form string are split the way a shell would separate words
# (plus the punctuation a command line, a ``--flag=value`` pair or a Markdown
# link wraps one in). Only a token that names a URL scheme is a candidate:
# treating every token as a host would make ``curl`` or ``POST`` a destination
# and refuse benign calls.
_TOKEN_SPLIT = re.compile(r"[\s'\"<>,;)|=\[\]()]+")
_SPECIAL_SCHEME_TOKEN = re.compile(r"^(?:https?|wss?|ftp):\S", re.IGNORECASE)
_SPECIAL_SCHEME_PREFIX = re.compile(r"^(?:https?|wss?|ftp):", re.IGNORECASE)


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
        if isinstance(hosts, str):
            hosts = (hosts,)
        canonical_hosts = set()
        for host in hosts:
            canonical = destination_host(host)
            if not canonical:
                raise ValueError(
                    "secret hosts must be URL or host names, got {!r}".format(host))
            canonical_hosts.add(canonical)
        if value is not None:
            source: Callable[[], str] = lambda v=value: v
        elif env is not None:
            source = lambda name=env: _from_env(name)
        elif file is not None:
            source = lambda path=file: _from_file(path)
        else:
            source = getter  # type: ignore[assignment]
        with self._lock:
            self._secrets[secret_id] = Secret(secret_id, allowed, frozenset(canonical_hosts),
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


def _url_tokens(text: str) -> Iterable[str]:
    """Every URL-looking token in a free-form string.

    A command line, a Markdown link or a templated body can carry a destination
    that no URL key names. Splitting on shell/Markdown punctuation and keeping
    only tokens with a URL scheme avoids turning ordinary words into hosts
    while still catching ``HTTPS://...`` and ``https:host`` spellings.
    """
    for token in _TOKEN_SPLIT.split(text):
        if "://" in token or _SPECIAL_SCHEME_TOKEN.match(token):
            yield token


def _urls(args: Any) -> Tuple[List[Tuple[str, bool]], bool]:
    """Walk ``args`` and return ``(candidates, unverifiable)``.

    ``candidates`` are ``(text, from_url_key)`` pairs: a string under a URL key
    at any depth, plus every scheme-bearing token in any other string. A URL
    key whose value is a container is walked, never stringified. The walk
    follows any ``Mapping``, ``Sequence`` or ``Set`` - not just ``dict`` and
    ``list`` - because a custom or read-only mapping is still a destination the
    caller can send to. The second item is True when a URL key holds a value
    that is neither a string nor a walkable container - a destination that
    cannot be verified at all, which the caller must refuse rather than skip.
    """
    candidates: List[Tuple[str, bool]] = []
    unverifiable = False

    def walk(node: Any, depth: int, url_key: bool) -> None:
        nonlocal unverifiable
        if depth > _MAX_DESTINATION_DEPTH:
            # Too deep to inspect: a destination could hide below this point,
            # so the call is unverifiable rather than silently unwalked.
            unverifiable = True
            return
        if isinstance(node, str):
            if url_key:
                candidates.append((node, True))
            for token in _url_tokens(node):
                if not url_key or token != node:
                    candidates.append((token, False))
            return
        if isinstance(node, Mapping):
            for key, value in node.items():
                key_is_url = isinstance(key, str) and key.strip().lower() in _URL_KEY_SET
                walk(value, depth + 1, url_key or key_is_url)
            return
        if isinstance(node, (Sequence, Set)) and not isinstance(node, (bytes, bytearray)):
            for item in node:
                walk(item, depth + 1, url_key)
            return
        if url_key:
            unverifiable = True

    walk(args, 0, False)
    return candidates, unverifiable


def _canonical_host(text: str, from_url_key: bool) -> Optional[str]:
    """The canonical host of one candidate, or None if it cannot be verified.

    A bare value under a URL key keeps today's ``https://`` prepend so
    ``api.acme.com:8443`` reads as an authority; every candidate then goes
    through A05's single canonical parser.
    """
    candidate = text
    if (from_url_key and "://" not in candidate
            and not _SPECIAL_SCHEME_PREFIX.match(candidate)):
        candidate = "https://" + candidate
    return destination_host(candidate)


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
            candidates, unverifiable = _urls(event.args)
            if unverifiable:
                return Decision.block(
                    "secret {!r} cannot verify the destination".format(secret_id),
                    POLICY_ID)
            if not candidates:
                return Decision.block(
                    "secret {!r} has no verifiable destination".format(secret_id),
                    POLICY_ID)
            for text, from_url_key in candidates:
                host = _canonical_host(text, from_url_key)
                if host is None:
                    return Decision.block(
                        "secret {!r} cannot verify the destination".format(secret_id),
                        POLICY_ID)
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


def _scrub_text(text: str, pairs: List[Tuple[str, str]]) -> str:
    for secret_id, secret in pairs:
        if secret in text:
            text = text.replace(secret, placeholder(secret_id))
    return text


def _scrub_bytes(value: Any, pairs: List[Tuple[str, str]]) -> Any:
    """Scrub a bytes/bytearray payload, preserving its concrete type.

    Decoding uses ``errors="replace"`` so a non-UTF-8 payload still comes back;
    when no secret matched the original object is returned untouched rather
    than a lossy re-encode of it.
    """
    text = bytes(value).decode("utf-8", errors="replace")
    scrubbed = _scrub_text(text, pairs)
    if scrubbed == text:
        return value
    encoded = scrubbed.encode("utf-8")
    return bytearray(encoded) if isinstance(value, bytearray) else encoded


def _differs(scrubbed: Any, original: Any) -> bool:
    """True when scrubbing actually changed a field.

    Identity is checked first so a walk that returned the very same object (a
    clean string, a clean content block) never triggers a copy. A comparison
    that itself raises is treated as a change - fail toward scrubbing.
    """
    if scrubbed is original:
        return False
    try:
        return bool(scrubbed != original)
    except Exception:
        return True


def _rebuild_container(kind: Any, items: Any) -> Any:
    """Rebuild a container as its own concrete type, preserving the class.

    ``kind`` is taken as ``Any`` so a call with an arbitrary container class is
    not mistaken for a zero-argument construction at type-check time.
    """
    return kind(items)


def _copy_with(value: Any, updates: Dict[str, Any]) -> Any:
    """``value`` with attributes replaced, as a copy - never the original.

    A shallow copy plus assignment preserves the concrete class (doubly so for
    a dataclass, where a frozen instance falls through to
    ``dataclasses.replace``). A pydantic model can be copied by ``model_copy``.
    If every copying strategy fails, the last resort still carries every field
    it can read from the original, so only the scrubbed fields change and the
    caller keeps the rest: losing the concrete type is better than handing back
    the original object with a live secret in it, but dropping unrelated fields
    is not acceptable either.
    """
    try:
        clone = copy.copy(value)
        for name, replacement in updates.items():
            setattr(clone, name, replacement)
        return clone
    except Exception:
        pass
    model_copy = getattr(value, "model_copy", None)
    if callable(model_copy):
        try:
            return model_copy(update=dict(updates))
        except Exception:
            pass
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        try:
            return dataclasses.replace(value, **updates)
        except Exception:
            pass
    fields: Dict[str, Any] = {}
    try:
        fields.update(vars(value))
    except Exception:
        pass
    slots = getattr(type(value), "__slots__", ())
    if isinstance(slots, str):
        slots = (slots,)
    for name in slots:
        if isinstance(name, str) and name not in fields:
            try:
                fields[name] = getattr(value, name)
            except Exception:
                continue
    fields.update(updates)
    return types.SimpleNamespace(**fields)


def _scrub_resource(item: Any, pairs: List[Tuple[str, str]], depth: int) -> Any:
    """Scrub an embedded resource's contents, preserving the block on a miss.

    MCP carries an ``EmbeddedResource`` block's payload under ``resource``:
    a ``TextResourceContents`` object (``resource.text``) or its dict form.
    Neither has a top-level ``text``, so a walk that only looks at the block
    itself would hand the value straight back.
    """
    resource = getattr(item, "resource", None)
    if resource is None:
        return item
    if isinstance(resource, Mapping):
        scrubbed = scrub(resource, depth)
        return item if not _differs(scrubbed, resource) else _copy_with(
            item, {"resource": scrubbed})
    text = getattr(resource, "text", None)
    if isinstance(text, str):
        masked = _scrub_text(text, pairs)
        if masked == text:
            return item
        return _copy_with(item, {"resource": _copy_with(resource, {"text": masked})})
    return item


def _scrub_block(item: Any, pairs: List[Tuple[str, str]], depth: int) -> Any:
    """One text-bearing block with its payload scrubbed, else ``item`` itself.

    A text block carries the string under ``text``; an embedded resource
    carries it under ``resource.text`` (or ``resource["text"]``). Both are
    scrubbed here. A block with neither is returned unchanged, so the caller
    can decide whether to fall back to a generic walk. This is the shared half
    of content-block scrubbing: it runs for a result's ``content`` list *and*
    for a block reached through an ordinary dict/list result, which is where a
    server can hide one.
    """
    text = getattr(item, "text", None)
    if isinstance(text, str):
        masked = _scrub_text(text, pairs)
        return item if masked == text else _copy_with(item, {"text": masked})
    return _scrub_resource(item, pairs, depth + 1)


def _scrub_content_item(item: Any, pairs: List[Tuple[str, str]], depth: int) -> Any:
    """One MCP content block with its payload text scrubbed, or a normal walk.

    A block with no text payload of its own falls back to the ordinary walk,
    so a block-shaped container is still traversed.
    """
    block = _scrub_block(item, pairs, depth)
    if block is not item:
        return block
    return scrub(item, depth)


def _scrub_result_object(value: Any, pairs: List[Tuple[str, str]], depth: int) -> Any:
    """Scrub an MCP-style result object, copying it only when it changed.

    The shape is ``content`` (a list of blocks) plus either
    ``structuredContent`` or ``structured_content``. Both spellings the SDK has
    used are scrubbed, and the object itself is never mutated. A field whose
    scrub changed nothing is left off the copy, so a clean result (even one
    whose ``content`` is an ordinary list) is returned as the very same object
    instead of being copied or reconstructed.
    """
    content = getattr(value, "content", None)
    updates: Dict[str, Any] = {}
    if isinstance(content, (list, tuple)):
        items = [_scrub_content_item(item, pairs, depth + 1) for item in content]
        rebuilt = tuple(items) if isinstance(content, tuple) else items
        if _differs(rebuilt, content):
            updates["content"] = rebuilt
    for name in ("structuredContent", "structured_content"):
        structured = getattr(value, name, None)
        if structured is not None:
            scrubbed = scrub(structured, depth + 1)
            if _differs(scrubbed, structured):
                updates[name] = scrubbed
    # An object with no content list (``content=None`` or absent) still gets
    # its structured payload scrubbed: that is where a resolved value hides
    # when the server returns only machine-readable output.
    if not updates:
        return value
    return _copy_with(value, updates)


def scrub(value: Any, depth: int = 0) -> Any:
    """``value`` with every resolved secret replaced by its placeholder.

    Handles strings, bytes/bytearray, any Mapping or Sequence (str and bytes
    excepted), and MCP-style result objects. Containers are rebuilt rather than
    mutated; the original is never changed.
    """
    store = get_store()
    if store is None:
        return value
    pairs = store.known_values()
    if not pairs:
        return value
    if isinstance(value, str):
        return _scrub_text(value, pairs)
    if isinstance(value, (bytes, bytearray)):
        return _scrub_bytes(value, pairs)
    if depth < 8:
        if isinstance(value, Mapping):
            items = {key: scrub(v, depth + 1) for key, v in value.items()}
            try:
                rebuilt = _rebuild_container(type(value), items)
                if len(rebuilt) == len(items):
                    return rebuilt
            except Exception:
                pass
            return items
        if isinstance(value, Set) and not isinstance(value, (str, bytes, bytearray)):
            # A set is not a Sequence: it has no order and no ``__getitem__``,
            # so an unhandled set result would hand a resolved value back.
            # Iterating twice over an unchanged set yields the same membership
            # order, which is enough to detect a hit without copying a clean
            # result.
            items = [scrub(v, depth + 1) for v in value]
            if all(new is old for new, old in zip(items, value)):
                return value
            try:
                return _rebuild_container(type(value), items)
            except Exception:
                return set(items)
        if isinstance(value, Sequence):
            items = [scrub(v, depth + 1) for v in value]
            try:
                rebuilt = _rebuild_container(type(value), items)
                if len(rebuilt) == len(items):
                    return rebuilt
            except Exception:
                pass
            return items
        result = _scrub_result_object(value, pairs, depth)
        if result is not value:
            return result
        # A text-bearing block reached through an ordinary dict/list result
        # (``{"content": [TextContent(text=...)]}``) is not itself a result
        # object, so the result path above never sees it. Scrub the block's own
        # payload here; a clean object comes back unchanged.
        block = _scrub_block(value, pairs, depth)
        if block is not value:
            return block
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

    # ``args`` is what will actually be filled and sent: by the time a
    # placeholder reaches this boundary a MODIFY rule may have rewritten it.
    # The destination bound has to be checked against *those* args, not the
    # pre-decision event snapshot, or a rewrite could retarget the call to a
    # host it was never allowed to reach. The receipt still digests the event
    # as the policy saw it (placeholders), so only the check input changes.
    check_event = dataclasses.replace(event, args=args)
    refused = check(check_event, ids)
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
