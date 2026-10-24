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
        # A special scheme carries an authority however the slashes are
        # spelled: any run (including none) of / and \ after the colon.
        (r"http:/\169.254.169.254/", "169.254.169.254"),
        (r"http:\169.254.169.254", "169.254.169.254"),
        ("http:///169.254.169.254/", "169.254.169.254"),
        (r"https:\\169.254.169.254/", "169.254.169.254"),
        ("http:169.254.169.254", "169.254.169.254"),
        ("HTTP://169.254.169.254/", "169.254.169.254"),
        ("ws://169.254.169.254/", "169.254.169.254"),
        ("wss://169.254.169.254/", "169.254.169.254"),
        ("ftp://169.254.169.254/", "169.254.169.254"),
        ("http://user@169.254.169.254/", "169.254.169.254"),
        ("http:user@169.254.169.254", "169.254.169.254"),
        # Every legacy and mapped literal spelling keeps working end to end.
        ("http://0x7f.1/", "0x7f.1"),
        ("http:2130706433", "2130706433"),
        ("http://0177.0.0.1/", "0177.0.0.1"),
        # A non-special scheme with no // is an opaque payload, not a host.
        ("mailto:user@example.com", None),
        ("data:text/html,x", None),
        # file: is not special: a bare file path names no network host.
        ("file:169.254.169.254", None),
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
        ("http://host:65535/", "host"),  # the last valid port
        ("http://host:/x", "host"),  # an empty port is still valid
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
        # The full WHATWG forbidden host code point set.
        ("http://host<.example/", None),
        ("http://host>.example/", None),
        ("http://a^b/", None),
        ("http://a|b/", None),
        ("peer://host\\evil.example/", None),
        # An out-of-range numeric port is a WHATWG parse error; an empty port
        # is still valid.
        ("http://host:70000/", None),
        ("http://host:65536/", None),
        ("http://[::1]:70000/", None),
        ("not a url", None),
        (None, None),
        (42, None),
        (["https://trusted.example"], None),
    ],
)
def test_destination_host(value, expected):
    assert destination_host(value) == expected


SPECIAL_SCHEME_LITERAL_SPELLINGS = (
    r"http:/\169.254.169.254/",
    r"http:\169.254.169.254",
    "http:///169.254.169.254/",
    r"https:\\169.254.169.254/",
    "http:169.254.169.254",
    "HTTP://169.254.169.254/",
    "https:169.254.169.254/x",
    "ws://169.254.169.254/",
    "wss://169.254.169.254/",
    "ftp://169.254.169.254/",
    "http://user@169.254.169.254/",
    "http:user@169.254.169.254",
)


def test_every_special_scheme_spelling_reaches_the_literal():
    # The A05b policy: there is no URL spelling of a host that a client dials
    # which this parser leaves as a bare host:port or an empty value, so the
    # private-IP and raw-IP guards always see the literal and classify it.
    # A value that is still None is malformed for WHATWG too, a non-special
    # scheme with no authority, a file: path, or a name; a name is not a
    # literal, so the IP guards have nothing to decide and the allowlists deny
    # the un-vettable value.
    for value in SPECIAL_SCHEME_LITERAL_SPELLINGS:
        assert destination_host(value) == "169.254.169.254", value


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
        # A special scheme needs no slashes at all before its authority.
        ("https:mcp.trusted.io/sse", "mcp.trusted.io"),
        ("https:/mcp.trusted.io/sse", "mcp.trusted.io"),
        (r"https:\mcp.trusted.io\sse", "mcp.trusted.io"),
        ("http:169.254.169.254/latest", "169.254.169.254"),
        # A bare host or email is not a URL authority: the caller blocks it.
        ("mcp.trusted.io", None),
        ("user@mcp.trusted.io", None),
        # A non-special scheme's opaque payload has no authority.
        ("mailto:user@example.com", None),
        ("file:169.254.169.254", None),
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
        # A non-special scheme does not end its authority at a backslash: it
        # stays in the authority and is rejected, so the host is never the
        # misleading prefix. With a backslash inside userinfo the runtime's
        # last-@ rule decides, exactly as for `https://`.
        (r"peer://host\evil", None),
        (r"peer://evil.example\@trusted.example", "trusted.example"),
        (r"peer://trusted.example\@evil.example", "evil.example"),
        ("peer://trusted.example%2eevil.example", "trusted.example.evil.example"),
        # The bare fallback is the whole lowercased text, never an email
        # domain: reducing it would admit a peer the allowlist never named.
        ("trusted.example", "trusted.example"),
        ("  Trusted.Example  ", "trusted.example"),
        ("user@trusted.example", "user@trusted.example"),
        ("peer:x", "peer:x"),
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
