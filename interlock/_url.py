"""Canonical destination parsing for the egress detectors.

The guards and the runtimes they protect do not read a URL the same way.
``urllib.parse.urlparse`` follows RFC 3986, while the HTTP clients an agent
calls follow WHATWG: in a special-scheme authority a backslash ends the host
(``https://evil.example\\@trusted.example/`` reaches ``evil.example``), the
userinfo separator is the last ``@`` after that rule, and the host is
percent-decoded before it is used. A guard that keeps the RFC reading can
compare an allowlisted name while the socket reaches a different host.

This module is the single extraction every egress guard uses. It is pure
standard library, opens no socket, and is deliberately fail-closed: anything
it cannot reduce to a host that survives one percent-decode and a character
check returns ``None``, which the allowlist guards treat as un-vettable and
therefore denied.

:func:`destination_host` reads a URL, a ``user@host`` address, or a bare
``host[:port][/path]``. :func:`url_host` is the strict URL-only form (a bare
host is not a URL). :func:`peer_host` keeps the A2A convention: a
``scheme://host`` is parsed canonically, while a bare peer is its whole
lowercased string, exactly as ``a2a_policy.peer_host`` always returned.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import unquote

# scheme "://". The scheme itself is irrelevant beyond ending an authority;
# peer:// and the special schemes are read the same way.
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")

# Characters that end an authority. Backslash is included because the runtimes
# treat it as a path delimiter inside an authority; query and fragment start a
# new component just as a slash does.
_AUTHORITY_END = "/\\?#"

# Characters a host may never contain after one percent-decode. Colon is
# handled separately: a bracketed IPv6 literal legitimately carries them.
_HOST_FORBIDDEN = frozenset("/\\@?#[]")


def _clean(value: Any) -> Optional[str]:
    """Strip a destination and drop the tab/CR/LF a runtime ignores."""
    if not isinstance(value, str):
        return None
    text = value.replace("\t", "").replace("\r", "").replace("\n", "").strip()
    return text or None


def _normalize(host: str) -> Optional[str]:
    """Percent-decode, validate, lowercase and de-dot a host, or return None.

    The decode happens exactly once. A host that still holds a ``%`` after it
    is therefore double-encoded and cannot name anything the caller could have
    allowlisted; delimiters, whitespace, control characters and non-ASCII are
    rejected for the same reason - the guard must not guess at a host it
    cannot compare against a reviewed name.
    """
    decoded = unquote(host)  # one decode; invalid UTF-8 becomes U+FFFD
    if "%" in decoded:
        return None
    for char in decoded:
        code = ord(char)
        if code < 0x20 or code == 0x7F or code > 0x7F or char.isspace():
            return None
        if char in _HOST_FORBIDDEN:
            return None

    if ":" in decoded:
        # Only a bracketed IPv6 authority may carry a colon. Validate it and
        # return the canonical spelling ipaddress itself accepts.
        try:
            address = ipaddress.ip_address(decoded)
        except ValueError:
            return None
        if address.version != 6:
            return None
        return str(address)

    normalized = decoded.lower()
    if normalized.endswith("."):  # exactly one trailing dot
        normalized = normalized[:-1]
    return normalized or None


def _split_authority(authority: str) -> Optional[str]:
    """The canonical host in *authority*, after the last ``@``, or None."""
    hostport = authority.rsplit("@", 1)[-1]
    if not hostport:
        return None

    if hostport.startswith("["):
        close = hostport.find("]")
        if close == -1 or ":" not in hostport[1:close]:
            return None
        remainder = hostport[close + 1:]
        if remainder:
            if not remainder.startswith(":") or not _valid_port(remainder[1:]):
                return None
        return _normalize(hostport[1:close])

    if ":" in hostport:
        if hostport.count(":") > 1:
            return None  # an unbracketed IPv6 authority is malformed
        host, port = hostport.split(":", 1)
        if not _valid_port(port):
            return None
        return _normalize(host)

    return _normalize(hostport)


def _valid_port(port: str) -> bool:
    return port == "" or port.isdigit()


def _parse(
    value: Any, *, require_scheme: bool, allow_bare: bool, allow_email: bool
) -> Optional[str]:
    text = _clean(value)
    if text is None:
        return None

    match = _SCHEME.match(text)
    if match:
        rest = text[match.end():]
        end = len(rest)
        for index, char in enumerate(rest):
            if char in _AUTHORITY_END:
                end = index
                break
        authority = rest[:end]
        if not authority:
            return None
        return _split_authority(authority)

    if require_scheme or not allow_bare:
        return None
    if "@" in text and not allow_email:
        return None

    end = len(text)
    for index, char in enumerate(text):
        if char in _AUTHORITY_END:
            end = index
            break
    return _split_authority(text[:end])


def destination_host(value: Any) -> Optional[str]:
    """Canonical host of a URL, a ``user@host`` address, or a bare host.

    Bare forms may carry a port and a path (``host:443/x``); an email is read
    as its domain, which is the destination an SMTP send reaches. Anything
    the parser cannot vet - malformed brackets, a residual percent sign, a
    delimiter inside the host, non-ASCII, a blank value - is ``None``.
    """
    return _parse(value, require_scheme=False, allow_bare=True, allow_email=True)


def url_host(value: Any) -> Optional[str]:
    """Canonical host of a URL that presents a ``scheme://`` authority, else None.

    A bare host is not a URL here: an MCP or HTTP connect that names no scheme
    has no authority to vet, and the allowlist guards that use this form fail
    closed on ``None``.
    """
    return _parse(value, require_scheme=True, allow_bare=False, allow_email=False)


def peer_host(value: Any) -> Optional[str]:
    """Canonical peer identity: a ``scheme://host``, or a bare peer's text.

    A peer may be written either as a ``scheme://host`` authority or as a bare
    name (``trusted.example``). The authority form is parsed like every other
    destination. The bare form is returned as the whole lowercased text, which
    is the historical ``a2a_policy.peer_host`` contract: splitting a bare
    ``user@host`` into its domain would turn a peer the allowlist never named
    into one it did.
    """
    text = _clean(value)
    if text is None:
        return None
    if _SCHEME.match(text):
        return _parse(text, require_scheme=True, allow_bare=False, allow_email=False)
    return text.lower()
