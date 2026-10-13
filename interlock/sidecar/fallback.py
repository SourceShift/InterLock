"""The offline fallback policy a sidecar publishes for when it is unreachable (R19).

A client that depends on a sidecar has three choices when the daemon is gone:

=============  =================================================================
``deny``       (default) every guarded call is blocked. Safe; the sidecar is an
               availability dependency.
``degraded``   evaluate the fallback policy the sidecar last published - a small
               declarative rule set (``--fallback-policy``) - locally, with no
               daemon. A missing, unsigned, tampered or stale file means deny.
``allow``      every guarded call is allowed, with a warning on every one.
=============  =================================================================

``degraded`` is never the default: interlock's real policy is arbitrary
Python, and an offline subset cannot claim to be equivalent to it. Keep the
fallback to the rules you would want standing with the daemon down - the
destructive denials, the egress allowlist - and nothing that needs the daemon.

The file is ``<socket>.fallback.json``::

    {"version": 1, "written_at": 1760000000,
     "policy": "<the policy document, as a JSON string>",
     "mac": "<hex HMAC-SHA256 of '<written_at>\\n<policy>' under the key>"}

The policy is carried as a string and the MAC covers those exact bytes, so the
Python and Node.js clients verify the same bytes without having to agree on a
JSON canonicalization. Fallback policies use an offline subset of the
declarative language that both clients evaluate identically: ``block`` and
``escalate`` rules whose conditions use all/any/not, ``action``, ``field`` and
``arg`` with ``eq ne in not_in gt ge lt le contains startswith endswith glob
exists``. No detectors, intents, regexes, rewrites or ``extends``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import time
from typing import Any, Dict, Mapping

FALLBACK_SUFFIX = ".fallback.json"
DEFAULT_MAX_AGE = 7 * 86400

OFFLINE_OPERATORS = frozenset(
    {"eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains", "startswith",
     "endswith", "glob", "exists"}
)
OFFLINE_RULE_KEYS = frozenset({"id", "verdict", "reason", "when", "locked", "on",
                               "description", "phase"})


class FallbackError(ValueError):
    """A fallback file or policy that cannot be used."""


def fallback_path(socket_path: str) -> str:
    return str(socket_path) + FALLBACK_SUFFIX


def validate_offline(doc: Mapping[str, Any]) -> None:
    """Raise :class:`FallbackError` unless ``doc`` uses only the offline subset."""
    if not isinstance(doc, dict):
        raise FallbackError("a fallback policy must be an object")
    extra = set(doc) - {"version", "name", "description", "rules"}
    if extra:
        raise FallbackError("fallback policies cannot use: {}".format(", ".join(sorted(extra))))
    rules = doc.get("rules", [])
    if not isinstance(rules, list) or not rules:
        raise FallbackError("a fallback policy needs at least one rule")
    for index, rule in enumerate(rules):
        where = "rules[{}]".format(index)
        if not isinstance(rule, dict):
            raise FallbackError("{}: not an object".format(where))
        bad = set(rule) - OFFLINE_RULE_KEYS
        if bad:
            raise FallbackError("{}: offline rules cannot use {}".format(where, ", ".join(sorted(bad))))
        if rule.get("verdict") not in ("block", "escalate"):
            raise FallbackError("{}: offline rules must block or escalate".format(where))
        if "when" not in rule:
            raise FallbackError("{}: needs 'when'".format(where))
        _validate_condition(rule["when"], where + ".when")


def _validate_condition(cond: Any, where: str) -> None:
    if not isinstance(cond, dict) or not cond:
        raise FallbackError("{}: not a condition".format(where))
    for key in ("all", "any"):
        if key in cond:
            parts = cond[key]
            if not isinstance(parts, list) or not parts:
                raise FallbackError("{}: {!r} needs a list".format(where, key))
            for i, part in enumerate(parts):
                _validate_condition(part, "{}.{}[{}]".format(where, key, i))
            return
    if "not" in cond:
        _validate_condition(cond["not"], where + ".not")
        return
    if set(cond) == {"action"}:
        return
    if "intent" in cond:
        raise FallbackError("{}: shell intents are not available offline".format(where))
    subject = "field" if "field" in cond else "arg" if "arg" in cond else None
    if subject is None:
        raise FallbackError("{}: unknown condition".format(where))
    ops = set(cond) - {subject}
    if len(ops) != 1 or not ops <= OFFLINE_OPERATORS:
        raise FallbackError("{}: offline operators are {}".format(
            where, ", ".join(sorted(OFFLINE_OPERATORS))))


def _mac(key: bytes, written_at: int, policy: str) -> str:
    message = "{}\n{}".format(written_at, policy).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def write_fallback(path: str, doc: Mapping[str, Any], key: bytes) -> Dict[str, Any]:
    """Validate, sign and atomically write a fallback file (mode 0600)."""
    validate_offline(doc)
    from ..policy.declarative import load_policy
    engine = load_policy(doc, source="fallback")  # it must also load as a policy
    if engine.quarantined:
        raise FallbackError("fallback rule(s) invalid: {}".format("; ".join(engine.quarantined)))
    policy = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    written_at = int(time.time())
    body = {"version": 1, "written_at": written_at, "policy": policy,
            "mac": _mac(key, written_at, policy)}
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fallback-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return body


def read_fallback(path: str, key: bytes, *, max_age: float = DEFAULT_MAX_AGE,
                  now: float = 0.0) -> Dict[str, Any]:
    """The verified fallback policy document. Raises :class:`FallbackError` for
    a missing, malformed, unsigned, tampered or stale file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            body = json.load(fh)
    except FileNotFoundError:
        raise FallbackError("no fallback policy at {}".format(path))
    except (OSError, ValueError) as exc:
        raise FallbackError("unreadable fallback policy: {}".format(exc))
    if not isinstance(body, dict) or body.get("version") != 1:
        raise FallbackError("not a fallback policy file")
    written_at, policy, mac = body.get("written_at"), body.get("policy"), body.get("mac")
    if not isinstance(written_at, int) or not isinstance(policy, str) or not isinstance(mac, str):
        raise FallbackError("fallback policy is unsigned or malformed")
    if not hmac.compare_digest(_mac(key, written_at, policy), mac):
        raise FallbackError("fallback policy signature does not verify")
    age = (now or time.time()) - written_at
    if age > max_age:
        raise FallbackError("fallback policy is stale ({:.0f}s old)".format(age))
    doc = json.loads(policy)
    validate_offline(doc)
    return doc
