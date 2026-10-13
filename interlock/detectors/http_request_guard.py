"""Rules over HTTP requests a tool makes: host, path, method and headers.

An egress allowlist says *where* a tool may send; this says *what* it may do
there. Each rule names conditions, all of which must hold for it to fire; the
first rule that fires decides::

    http_request_guard(rules=[
        {"name": "no-admin-api", "resources": ["/admin/**"],
         "message": "the admin API is off limits"},
        {"name": "read-only-billing", "hosts": ["billing.acme.com"],
         "methods": ["POST", "PUT", "PATCH", "DELETE"], "verdict": "escalate"},
        {"name": "no-debug-header", "headers": {"x-debug": ["*"]}},
        {"name": "service-token-only", "hosts": ["*.internal"],
         "headers_not": {"authorization": ["Bearer svc_*"]}},
    ])

=================  ==========================================================
``hosts``          host globs (``*.acme.com``)
``resources``      path globs: ``*`` is one segment, a trailing ``/**`` is
                   that path and everything under it
``methods``        HTTP methods; read from a ``method`` argument, else
                   inferred from the tool name (``http_post`` -> POST)
``headers``        name -> value globs; fires when a header has a matching
                   value (all names must match, any value per name)
``headers_not``    name -> the allowed value globs; fires when the header is
                   missing or matches none of them
``verdict``        ``block`` (default) or ``escalate``; ``message`` is the
                   reason given
=================  ==========================================================

The URL comes from ``url``/``endpoint``/``uri`` arguments, headers from a
``headers`` object. Header names compare case-insensitively.
"""
from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import Rule

POLICY_ID = "http_request"
_RULE_KEYS = frozenset({"name", "hosts", "resources", "methods", "headers", "headers_not",
                        "verdict", "message"})
_URL_KEYS = ("url", "endpoint", "uri")
_METHOD_WORDS = ("delete", "patch", "put", "post", "head", "options", "get")


def resource_matches(pattern: str, path: str) -> bool:
    """``*`` matches one segment; a trailing ``/**`` matches the path and below."""
    path = "/" + path.strip("/")
    if pattern.endswith("/**"):
        base = "/" + pattern[:-3].strip("/")
        return resource_matches(base, path) or _segments_glob(base.rstrip("/") + "/*", path, deep=True)
    return _segments_glob("/" + pattern.strip("/"), path, deep=False)


def _segments_glob(pattern: str, path: str, *, deep: bool) -> bool:
    want = pattern.strip("/").split("/") if pattern.strip("/") else []
    have = path.strip("/").split("/") if path.strip("/") else []
    if deep:
        if len(have) < len(want):
            return False
        have = have[:len(want)]
    if len(want) != len(have):
        return False
    return all(fnmatch.fnmatchcase(h, w) for w, h in zip(want, have))


class _HttpRule:
    def __init__(self, raw: Mapping[str, Any]) -> None:
        if not isinstance(raw, Mapping) or set(raw) - _RULE_KEYS:
            raise ValueError("an http rule takes {}".format(", ".join(sorted(_RULE_KEYS))))
        self.name = str(raw.get("name") or "http-rule")
        self.hosts = [h.lower() for h in raw.get("hosts", [])]
        self.resources = list(raw.get("resources", []))
        self.methods = [m.upper() for m in raw.get("methods", [])]
        self.headers = {k.lower(): list(v) for k, v in (raw.get("headers") or {}).items()}
        self.headers_not = {k.lower(): list(v) for k, v in (raw.get("headers_not") or {}).items()}
        self.verdict = raw.get("verdict", "block")
        if self.verdict not in ("block", "escalate"):
            raise ValueError("verdict must be block or escalate")
        self.message = raw.get("message") or "request refused by http rule {}".format(self.name)
        if not (self.hosts or self.resources or self.methods or self.headers or self.headers_not):
            raise ValueError("http rule {!r} has no condition".format(self.name))

    def fires(self, host: str, path: str, method: Optional[str], headers: Dict[str, str]) -> bool:
        if self.hosts and not any(fnmatch.fnmatchcase(host, h) for h in self.hosts):
            return False
        if self.resources and not any(resource_matches(r, path) for r in self.resources):
            return False
        if self.methods and method is not None and method not in self.methods:
            return False
        for name, patterns in self.headers.items():
            value = headers.get(name)
            if value is None or not any(fnmatch.fnmatchcase(value, p) for p in patterns):
                return False
        if self.headers_not:
            violated = any(headers.get(name) is None or not any(
                fnmatch.fnmatchcase(headers[name], p) for p in patterns)
                for name, patterns in self.headers_not.items())
            if not violated:
                return False
        return True


def http_request_guard(rules: Sequence[Mapping[str, Any]], *,
                       actions: Optional[Iterable[str]] = None) -> Rule:
    """Build a Rule enforcing HTTP request rules (see the module docstring)."""
    compiled = [_HttpRule(r) for r in rules]
    if not compiled:
        raise ValueError("http_request_guard needs at least one rule")
    action_set = None if actions is None else frozenset(actions)

    def rule(event: SensorEvent) -> Optional[Decision]:
        if action_set is not None and event.action not in action_set:
            return None
        args = getattr(event, "args", None)
        if not isinstance(args, dict):
            return None
        key = next((k for k in _URL_KEYS if isinstance(args.get(k), str)), None)
        if key is None:
            return None
        parts = urlsplit(args[key] if "://" in args[key] else "https://" + args[key])
        host = (parts.hostname or "").lower()
        method = _method(event.action, args)
        headers = {str(k).lower(): str(v) for k, v in (args.get("headers") or {}).items()} \
            if isinstance(args.get("headers"), dict) else {}
        for http_rule in compiled:
            if http_rule.fires(host, parts.path or "/", method, headers):
                make = Decision.block if http_rule.verdict == "block" else Decision.escalate
                return make("http_request: {} ({})".format(http_rule.message, http_rule.name),
                            POLICY_ID, attributed_to=key)
        return None

    return rule


def _method(action: str, args: Mapping[str, Any]) -> Optional[str]:
    method = args.get("method")
    if isinstance(method, str) and method:
        return method.upper()
    lowered = action.lower()
    for word in _METHOD_WORDS:
        if re.search(r"(^|[_.\-/]){}($|[_.\-/])".format(word), lowered):
            return word.upper()
    return None
