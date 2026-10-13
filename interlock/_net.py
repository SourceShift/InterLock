"""Shared host parsing for the egress detectors.

:func:`ipaddress.ip_address` reads only the dotted-quad and IPv6 spellings, but
the clients an agent dials through (curl, browsers, ``getaddrinfo``) also take
the legacy ``inet_aton`` forms: ``http://2130706433/`` and ``http://0x7f.1/``
both reach ``127.0.0.1``. A guard that treats those as domain names lets a raw
address walk past it, so every egress detector judges a host through
:func:`ip_literal` instead.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional, Union

Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# One part of a legacy IPv4 literal: hex (``0x7f``), octal (``0177``) or decimal.
_PART = re.compile(r"^(?:0[xX][0-9a-fA-F]*|[0-9]+)$")


def _part_value(part: str) -> Optional[int]:
    if not _PART.match(part):
        return None
    if part[:2].lower() == "0x":
        return int(part[2:] or "0", 16)
    if len(part) > 1 and part[0] == "0":
        return int(part, 8) if all(c in "01234567" for c in part) else None
    return int(part)


def _legacy_ipv4(host: str) -> Optional[ipaddress.IPv4Address]:
    """``a``, ``a.b``, ``a.b.c`` or ``a.b.c.d`` with per-part radix, as inet_aton reads it."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for p in parts:
        v = _part_value(p)
        if v is None:
            return None
        values.append(v)
    *head, last = values
    if any(v > 255 for v in head) or last >= 256 ** (5 - len(parts)):
        return None
    number = 0
    for v in head:
        number = number * 256 + v
    return ipaddress.IPv4Address(number * 256 ** (5 - len(parts)) + last)


def ip_literal(host: str) -> Optional[Address]:
    """The address *host* dials when it is an IP literal in any spelling, else None.

    An IPv4-mapped IPv6 literal (``::ffff:169.254.169.254``) is returned as the
    IPv4 address it reaches. A name - anything with a non-numeric label - is None.
    """
    host = host.strip().rstrip(".")
    if not host:
        return None
    try:
        address: Address = ipaddress.ip_address(host)
    except ValueError:
        legacy = _legacy_ipv4(host)
        return legacy
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address
