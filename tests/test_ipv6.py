import re
import pytest

from klp import BUILTIN_REGEXES

ipv6_regex = BUILTIN_REGEXES["ipv6"][0]
pattern = re.compile(ipv6_regex)

valid_ipv6_addresses = [
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # full notation
    "2001:db8:85a3::8a2e:370:7334",  # compressed notation
    "::1",  # loopback
    "fe80::1",  # link-local
    "2001:db8::",  # compressed at end
    "::ffff:192.0.2.128",  # IPv4-mapped IPv6
    "2001:0db8:0000:0000:0000:0000:1428:57ab",  # full notation variant
    "2001:db8::1428:57ab",  # compressed variant
]

invalid_ipv6_addresses = [
    "2001:db8:85a3:0:0:8a2e:370:7334:",  # trailing colon
    "2001:db8:85a3::8a2e::7334",  # two '::'
    "12345::",  # block value too large
    "2001:db8:85a3:0000:0000:8a2e:0370",  # only 7 groups
    "2001:db8:85a3:0000:0000:8a2e:0370:7334:1234",  # 9 groups
    "gggg:db8::1",  # invalid hex characters
    "4",  # Too short for our purposes
]


@pytest.mark.parametrize("address", valid_ipv6_addresses)
def test_valid_ipv6(address):
    """
    Test that valid IPv6 addresses are matched entirely by the regex.
    """
    # Using search ensures that our lookaround assertions capture the full address.
    match = pattern.search(address)
    assert match is not None, f"Valid IPv6 address '{address}' was not matched."
    # Check that the matched substring equals the entire address.
    assert (
        match.group(1) == address
    ), f"Regex did not capture the full address: {address}"


@pytest.mark.parametrize("address", invalid_ipv6_addresses)
def test_invalid_ipv6(address):
    """
    Test that invalid IPv6 addresses are not matched by the regex.
    """
    match = pattern.search(address)
    assert match is None, f"Invalid IPv6 address '{address}' should not be matched."


def test_ipv6_in_text():
    """
    Test that the regex correctly extracts an IPv6 address embedded in text.
    """
    text = "The server at 2001:db8:85a3::8a2e:370:7334 is reachable."
    match = pattern.search(text)
    expected = "2001:db8:85a3::8a2e:370:7334"
    assert match is not None, "IPv6 address not found in the text."
    assert (
        match.group(1) == expected
    ), "Regex did not extract the full IPv6 address from text."


def test_ipv6_with_adjacent_non_ipv6_characters():
    """
    Test that the regex does not accidentally capture parts of a string when adjacent
    characters are not part of a valid IPv6 address.
    """
    text = "Address:[2001:db8::1] is the loopback."
    match = pattern.search(text)
    expected = "2001:db8::1"
    assert match is not None, "IPv6 address not found within the brackets."
    assert (
        match.group(1) == expected
    ), "Regex did not correctly extract the IPv6 address from within brackets."
