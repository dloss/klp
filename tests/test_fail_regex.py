import re
import pytest

from klp import BUILTIN_REGEXES

PATTERN = BUILTIN_REGEXES["fail"][0]
regex = re.compile(PATTERN)


# Positive test cases: strings that should trigger a match.
@pytest.mark.parametrize(
    "text",
    [
        "error",
        "Error",
        "err",
        "fail",
        "failure",
        "failed",
        "failing",
        "deny",
        "denied",
        "invalid",
        "timeout",
        "time out",
        "timed out",
        "time-out",
        "timout",
        "exception",
        "blocked",
        "expired",
        "expiring",
        "expiration",
        "expire",
        "rejected",
        "rejecting",
        "rejection",
        "unauthorized",
        "unauthorize",
        "unauthorization",
        "unauth",
        "forbidden",
        "corrupt",
        "corrupted",
        "corruption",
        "malform",
        "malformed",
        "malformation",
        "disconnect",
        "disconnected",
        "disconnection",
        "unreachable",
        "violat",
        "violate",
        "violated",
        "violation",
        "blacklist",
        "blacklisted",
        "blacklisting",
        "crash",
        "crashed",
        "crashing",
        "abort",
        "aborted",
        "aborting",
        "panic",
        "crit",
        "critical",
        "alert",
        "fatal",
        "emerg",
        "emergency",
        # Cases within sentences and with punctuation
        "An error occurred.",
        "Operation failed!",
        "Connection timeout.",
        "Exception thrown, please check.",
        "User denied access.",
        "System panic imminent.",
        "Critical error encountered.",
        "Alert: System overload.",
        "Fatal flaw in design.",
        "Emergency stop activated.",
    ],
)
def test_positive_matches(text):
    match = regex.search(text)
    assert match is not None, f"Expected a match in: {text}"


# Negative test cases: strings that should not match.
@pytest.mark.parametrize(
    "text",
    [
        "successful",
        "healthy",
        "operation completed",
        "info",
        "warning",
        "errand",  # 'err' as part of a longer word
        "failureful",  # extra letters after 'failure'
        "authorize",  # not "unauthorize" or "unauthorized"
        "disconnectedly",  # extra suffix after 'disconnected'
        "violationary",  # extra letters after 'violation'
        "crasher",  # not exactly 'crash'
        "abortion",  # different word form
        "exceptional",  # extra letters after 'exception'
        "blockedness",  # extra characters
        "timepiece",  # false positive check
        "expiredd",  # extra letter at the end
        "malformedly",  # extra suffix
        "panicking",  # extra suffix, should not match exactly "panic"
        "critiqued",  # false positive for "crit"
        "alerting",  # false positive for "alert"
        "fatality",  # extra letters after "fatal"
        "emergencyed",  # extra suffix after "emergency"
    ],
)
def test_negative_matches(text):
    match = regex.search(text)
    assert match is None, f"Did not expect a match in: {text}"


# Test that keywords embedded in larger words are not falsely matched.
def test_word_boundaries():
    text = "The errand was delivered."
    match = regex.search(text)
    assert match is None, "Embedded 'err' in 'errand' should not match."

    text2 = "The failureful process did not trigger any alerts."
    match2 = regex.search(text2)
    assert match2 is None, "Embedded negative term with extra suffix should not match."


# Test that multiple occurrences are captured.
def test_multiple_occurrences():
    text = "error, timeout, and crash all occurred during the process."
    matches = regex.findall(text)
    expected_keywords = ["error", "timeout", "crash"]
    for keyword in expected_keywords:
        assert any(
            keyword.lower() == m.lower() for m in matches
        ), f"Expected to find '{keyword}' in matches."


# Test punctuation boundaries.
def test_punctuation_boundaries():
    text = "System reported a 'failure.' near the server."
    match = regex.search(text)
    assert (
        match is not None
    ), "Expected a match for 'failure' with trailing punctuation."
    assert (
        match.group(0).lower() == "failure"
    ), f"Expected 'failure', got {match.group(0)}"


# Test sentences that include the new keywords.
def test_new_keywords_in_sentence():
    text = (
        "Panic ensued as the system encountered a fatal error, triggering "
        "a critical alert and emergency protocols."
    )
    matches = regex.findall(text)
    expected_keywords = ["panic", "fatal", "error", "critical", "alert", "emergency"]
    for keyword in expected_keywords:
        assert any(
            keyword.lower() == m.lower() for m in matches
        ), f"Expected to find '{keyword}' in matches."
