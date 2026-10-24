"""Canonical destination parser: table-driven WHATWG-vs-urlparse differentials,
the benign forms a destination may legitimately take, and fail-closed input.

The parser is the one host extractor the five egress guards share. These cases
pin the answers directly so a caller cannot quietly grow a second reading of a
URL; the caller test files pin that each guard consumes the answer.
"""
from urllib.parse import urlparse

import pytest

from interlock._url import destination_host, peer_host, url_host


# --- destination_host: URL, user@host, and bare host forms ------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # WHATWG / urlparse differentials: a browser ends a special-scheme
        # authority at a backslash, urlparse keeps everything after the @.
        (r"https://evil.example\@trusted.example/x", "evil.example"),
        (r"https://trusted.example\@evil.example/x", "trusted.example"),
        (r"http://169.254.169.254\@api.example.com/latest", "169.254.169.254"),
        # The last @ after that rule is the userinfo separator, nothing else.
        ("https://evil.example@trusted.example/", "trusted.example"),
        ("https://user:pass@trusted.example/x", "trusted.example"),
        # One percent-decode; a lookalike must never land on the allowed name.
        ("https://trusted.example%2eevil.example/", "trusted.example.evil.example"),
        ("https://evil.example%00.trusted.example/", None),
        ("https://api.acme.com%25.evil.example/", None),
        ("https://api.acme.com%252eevil.example/", None),
        ("https://trusted.example%2f.evil.example/", None),
        # Case, one trailing dot, and transport detail.
        ("https://TRUSTED.EXAMPLE./x", "trusted.example"),
        ("https://trusted.example../x", "trusted.example."),
        ("wss://mcp.trusted.io:8443/v2?token=1", "mcp.trusted.io"),
        ("ftp://Files.Example/x", "files.example"),
        # Surrounding whitespace and the tab/CR/LF a runtime drops.
        ("  https://api.acme.com/x  ", "api.acme.com"),
        ("https://api.acme.com\t/x", "api.acme.com"),
        ("https://api.acme.com\r\n/x", "api.acme.com"),
        # Bare host[:port][/path] and email-domain forms.
        ("trusted.example", "trusted.example"),
        ("trusted.example:443/x", "trusted.example"),
        ("user@trusted.example", "trusted.example"),
        ("user@Trusted.Example.", "trusted.example"),
        # Bracket IPv6 is returned in the form ipaddress accepts.
        ("http://[::1]:8080/", "::1"),
        ("[::1]:8080", "::1"),
        ("http://[2001:DB8::1]/x", "2001:db8::1"),
        ("http://[::ffff:169.254.169.254]/latest/", "::ffff:169.254.169.254"),
        # Fail closed: nothing vettable.
        ("", None),
        ("   ", None),
        ("https://", None),
        ("https://[::1", None),
        ("https://[trusted.example]/x", None),
        ("https://trüst.example/x", None),
        ("https://trusted.example:notaport/x", None),
        ("not a url", None),
        (None, None),
        (42, None),
        (["https://trusted.example"], None),
    ],
)
def test_destination_host(value, expected):
    assert destination_host(value) == expected


def test_destination_host_disagrees_with_urlparse_on_the_bypass():
    # The whole point of the shared parser: urlparse names the allowlisted
    # host, the runtime reaches the other one.
    value = r"https://evil.example\@trusted.example/x"
    assert urlparse(value).hostname == "trusted.example"
    assert destination_host(value) == "evil.example"


# --- url_host: the strict URL-only form the MCP allowlist uses --------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://mcp.trusted.io/sse", "mcp.trusted.io"),
        ("wss://mcp.trusted.io:8443/gateway", "mcp.trusted.io"),
        (r"https://evil.io\@mcp.trusted.io/sse", "evil.io"),
        # A bare host or email is not a URL authority: the caller blocks it.
        ("mcp.trusted.io", None),
        ("user@mcp.trusted.io", None),
        ("not a url", None),
        ("https://", None),
        ("https://[::1", None),
        ("file:///etc/passwd", None),
    ],
)
def test_url_host(value, expected):
    assert url_host(value) == expected


# --- peer_host: authority parsed canonically, bare peer preserved -----------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("peer://trusted.example", "trusted.example"),
        ("PEER://Trusted.Example:8443/send?x=1", "trusted.example"),
        ("peer://evil.example@trusted.example", "trusted.example"),
        (r"peer://evil.example\@trusted.example", "evil.example"),
        (r"peer://trusted.example\@evil.example", "trusted.example"),
        ("peer://trusted.example%2eevil.example", "trusted.example.evil.example"),
        # The bare fallback is the whole lowercased text, never an email
        # domain: reducing it would admit a peer the allowlist never named.
        ("trusted.example", "trusted.example"),
        ("  Trusted.Example  ", "trusted.example"),
        ("user@trusted.example", "user@trusted.example"),
        # Fail closed on a malformed authority.
        ("peer://[::1", None),
        ("peer://", None),
        ("", None),
        (None, None),
        (3, None),
    ],
)
def test_peer_host(value, expected):
    assert peer_host(value) == expected
