"""ip_literal reads a host the way the client that dials it does: every IPv4
spelling inet_aton accepts, IPv6, and IPv4-mapped IPv6, while names stay names."""
import pytest

from interlock._net import ip_literal


@pytest.mark.parametrize("host, address", [
    ("127.0.0.1", "127.0.0.1"),
    ("2130706433", "127.0.0.1"),            # one 32-bit decimal number
    ("0x7f.1", "127.0.0.1"),                # hex, short form
    ("0177.0.0.1", "127.0.0.1"),            # octal
    ("127.1", "127.0.0.1"),                 # a.b: last part fills 24 bits
    ("10.1.258", "10.1.1.2"),               # a.b.c: last part fills 16 bits
    ("2852039166", "169.254.169.254"),      # the metadata endpoint
    ("127.0.0.1.", "127.0.0.1"),            # trailing FQDN dot
    ("::1", "::1"),
    ("::ffff:169.254.169.254", "169.254.169.254"),  # IPv4-mapped: the v4 it reaches
])
def test_every_spelling_resolves_to_the_address_dialled(host, address):
    assert str(ip_literal(host)) == address


@pytest.mark.parametrize("host", [
    "example.com", "1e100.net", "8.8.8.8.example", "256.1.1.1", "1.2.3.4.5",
    "4294967296", "09.1.1.1", "0x1g", "", ".",
])
def test_names_and_out_of_range_values_are_not_addresses(host):
    assert ip_literal(host) is None
