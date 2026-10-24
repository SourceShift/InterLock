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
host is not a URL). :func:`peer_host` keeps the A2A convention: an authority
URL is parsed canonically, while a bare peer is its whole lowercased string,
exactly as ``a2a_policy.peer_host`` always returned.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import unquote

# A scheme prefix. WHATWG accepts a special scheme with any number of slashes
# (including none) before its authority, so the "//" is not part of the match.
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")

# Schemes that always carry an authority for a URL runtime. ``file`` is
# deliberately absent: ``file:relative/path`` has an empty host, so reading its
# path as an authority would invent a destination.
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})

# Characters that end a bare/email authority. Backslash is included because the
# runtimes treat it as a path delimiter inside such an authority; query and
# fragment start a new component just as a slash does.
_AUTHORITY_END = "/\\?#"

# Characters that end a non-special scheme's ``//`` authority. A backslash is
# not a delimiter there: it stays in the authority and _normalize rejects it.
_GENERIC_AUTHORITY_END = "/?#"

# Characters a host may never contain after one percent-decode. Colon is
# handled separately: a bracketed IPv6 literal legitimately carries them.
_HOST_FORBIDDEN = frozenset("/\\@?#[]<>^|")


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
    if port == "":
        return True
    # isascii() guards the Unicode digits where isdigit() is True but int()
    # raises (for example U+00B2); WHATWG also treats > 65535 as a parse error.
    return port.isascii() and port.isdigit() and int(port) <= 65535


def _authority_until(rest: str, delimiters: str) -> str:
    for index, char in enumerate(rest):
        if char in delimiters:
            return rest[:index]
    return rest


def _special_authority(rest: str) -> Optional[str]:
    """The host of a special scheme's authority, or None.

    WHATWG skips any run - including zero - of slashes and backslashes after
    ``scheme:``, so ``http:host``, ``http:/host``, ``http:///host`` and
    ``http:\\host`` all name the same authority.
    """
    index = 0
    while index < len(rest) and rest[index] in "/\\":
        index += 1
    authority = _authority_until(rest[index:], _AUTHORITY_END)
    if not authority:
        return None
    return _split_authority(authority)


def _generic_authority(rest: str) -> Optional[str]:
    """The host of a non-special scheme's ``//`` authority, or None."""
    authority = _authority_until(rest[2:], _GENERIC_AUTHORITY_END)
    if not authority:
        return None
    return _split_authority(authority)


def _is_bare_port_tail(rest: str) -> bool:
    """True when the text after a scheme-like prefix is just a port.

    The prefix match cannot tell ``trusted.example:443/x`` (a bare host and
    port) from ``mailto:user@host`` (an opaque payload). A bare host's tail is
    a decimal port up to the path, query, or fragment; anything else - an
    email payload, a ``data:`` blob, a ``file:`` path - names no host and must
    stay un-vettable rather than be read as an authority.
    """
    head = _authority_until(rest, _AUTHORITY_END)
    return bool(head) and head.isascii() and head.isdigit()


def _parse(
    value: Any, *, require_scheme: bool, allow_bare: bool, allow_email: bool
) -> Optional[str]:
    text = _clean(value)
    if text is None:
        return None

    match = _SCHEME.match(text)
    if match:
        scheme = match.group(1).lower()
        rest = text[match.end():]
        if scheme in _SPECIAL_SCHEMES:
            return _special_authority(rest)
        if rest.startswith("//"):
            return _generic_authority(rest)
        # A non-special scheme with no "//" has no authority. It may still be
        # a bare host:port, but only when the tail is a port rather than an
        # opaque payload such as mailto:user@host or file:relative/path.
        if require_scheme or not allow_bare or not _is_bare_port_tail(rest):
            return None

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
    """Canonical host of a URL that presents a scheme with an authority, else None.

    A special scheme carries an authority however its slashes are spelled
    (``https:host``, ``https:/host`` and ``https:\\host`` included); any other
    scheme needs the ``//`` form. A bare host is not a URL here: an MCP or HTTP
    connect that names no scheme has no authority to vet, and the allowlist
    guards that use this form fail closed on ``None``.
    """
    return _parse(value, require_scheme=True, allow_bare=False, allow_email=False)


def peer_host(value: Any) -> Optional[str]:
    """Canonical peer identity: an authority URL, or a bare peer's text.

    A peer may be written either as a ``special-scheme:``/``scheme://host``
    authority or as a bare name (``trusted.example``). The authority form is
    parsed like every other destination, so a non-special scheme's backslash
    stays in the authority and makes the peer un-vettable rather than naming a
    misleading host. Anything else - ``peer:x`` included - is returned as the
    whole lowercased text, which is the historical ``a2a_policy.peer_host``
    contract: splitting a bare ``user@host`` into its domain would turn a peer
    the allowlist never named into one it did.
    """
    text = _clean(value)
    if text is None:
        return None
    match = _SCHEME.match(text)
    if match is not None:
        scheme = match.group(1).lower()
        rest = text[match.end():]
        if scheme in _SPECIAL_SCHEMES or rest.startswith("//"):
            return _parse(
                text, require_scheme=True, allow_bare=False, allow_email=False
            )
    return text.lower()
