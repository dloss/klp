import re
import pytest

from klp import BUILTIN_REGEXES

ipv4_regex = BUILTIN_REGEXES["ipv4"][0]
ipv4_port_regex = BUILTIN_REGEXES["ipv4_port"][0]

# Compile the regexes.
pattern_ipv4 = re.compile(ipv4_regex)
pattern_ipv4_port = re.compile(ipv4_port_regex)


# ------------------ Tests for IPv4 ------------------

valid_ipv4_addresses = [
    "192.168.0.1",
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
]

invalid_ipv4_addresses = [
    "256.100.50.25",  # 256 is invalid.
    "192.168.0",  # only 3 octets.
    "192.168.0.1.5",  # 5 octets; should not be recognized as a valid IP.
    "192.168.01.1",  # Octet with leading 0 (considered invalid here).
    "192.168.0.-1",  # Negative octet.
    "192.168.0.1a",  # Extra letters.
]


@pytest.mark.parametrize("address", valid_ipv4_addresses)
def test_valid_ipv4(address):
    """
    Test that valid IPv4 addresses are fully matched as the entire string
    (the match, group 0, is exactly the IPv4 address).
    """
    match = pattern_ipv4.fullmatch(address)
    assert match is not None, f"IPv4 address '{address}' was not matched."
    assert (
        match.group(0) == address
    ), f"Regex did not capture the full IPv4 address in group 0: {address}"


@pytest.mark.parametrize("address", invalid_ipv4_addresses)
def test_invalid_ipv4(address):
    """
    Test that invalid IPv4 addresses are not matched.
    """
    match = pattern_ipv4.fullmatch(address)
    assert match is None, f"Invalid IPv4 address '{address}' should not be matched."


def test_ipv4_in_text():
    """
    Test that an IPv4 address is correctly extracted from a text.
    """
    text = "The device is located at 192.168.1.100 in the network."
    match = pattern_ipv4.search(text)
    expected = "192.168.1.100"
    assert match is not None, "IPv4 address not found in the text."
    assert (
        match.group(0) == expected
    ), "Regex did not extract the full IPv4 address from text."


# ------------------ Tests for IPv4:Port ------------------

valid_ipv4_port_addresses = [
    "192.168.0.1:80",
    "127.0.0.1:65535",
    "0.0.0.0:0",
    "255.255.255.255:8080",
]

invalid_ipv4_port_addresses = [
    "192.168.0.1",  # No port present.
    "192.168.0.1:65536",  # Port outside the allowed range.
    "256.168.0.1:80",  # Invalid IPv4 address.
    "192.168.0.1:-80",  # Negative port.
    "192.168.0.1:080",  # Port with multiple digits and a leading zero.
    "192.168.0.1:port",  # Port is not numeric.
]


@pytest.mark.parametrize("address", valid_ipv4_port_addresses)
def test_valid_ipv4_port(address):
    """
    Test that valid IPv4:Port addresses are fully matched as the entire string
    (the match, group 0, is exactly the IPv4:port string).
    """
    match = pattern_ipv4_port.fullmatch(address)
    assert match is not None, f"IPv4 with port '{address}' was not matched."
    assert (
        match.group(0) == address
    ), f"Regex did not capture the full IPv4:port string in group 0: {address}"


@pytest.mark.parametrize("address", invalid_ipv4_port_addresses)
def test_invalid_ipv4_port(address):
    """
    Test that invalid IPv4:Port addresses are not matched.
    """
    match = pattern_ipv4_port.fullmatch(address)
    assert match is None, f"Invalid IPv4 with port '{address}' should not be matched."


def test_ipv4_port_in_text():
    """
    Test that IPv4:Port addresses are correctly extracted from a text.
    """
    text = (
        "2023-03-19T19:05:14.875867Z d427334e2c32 New connection: "
        "43.134.47.100:46694 (10.0.0.142:9090) [session: d427334e2c32]"
    )
    # Use findall to extract all IPv4:port occurrences.
    matches = pattern_ipv4_port.findall(text)
    expected = ["43.134.47.100:46694", "10.0.0.142:9090"]
    assert matches == expected, f"Expected {expected}, got {matches}"
