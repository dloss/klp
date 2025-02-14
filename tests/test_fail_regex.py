import re
import pytest

from klp import BUILTIN_REGEXES

PATTERN = BUILTIN_REGEXES["fail"][0]
regex = re.compile(PATTERN)


# Positive test cases: strings that should contain a negative event keyword.
@pytest.mark.parametrize(
    "text",
    [
        "abnormal",
        "abnormally",
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
        # With surrounding punctuation and within sentences
        "An error occurred.",
        "Operation failed!",
        "Connection timeout.",
        "Exception thrown, please check.",
        "User denied access.",
    ],
)
def test_positive_matches(text):
    match = regex.search(text)
    assert match is not None, f"Expected a match in: {text}"


# Negative test cases: strings that should NOT match the regex.
@pytest.mark.parametrize(
    "text",
    [
        "successful",
        "healthy",
        "operation completed",
        "info",
        "warning",
        "errand",  # 'err' is part of 'errand', not a standalone word.
        "failureful",  # extra letters prevent an exact word boundary match.
        "authorize",  # should not match because it's not "unauthorize" or "unauthorized"
        "disconnectedly",  # extra suffix after 'disconnected'
        "violationary",  # extra letters after 'violation'
        "crasher",  # not exactly 'crash'
        "abortion",  # different word form
        "exceptional",  # extra letters after 'exception'
        "blockedade",  # extra characters
        "timepiece",  # false positive check
        "expiredd",  # extra letter at the end
        "malformedly",  # extra suffix
    ],
)
def test_negative_matches(text):
    match = regex.search(text)
    assert match is None, f"Did not expect a match in: {text}"


# Test that embedded keywords inside longer words do not falsely match.
def test_word_boundaries():
    text = "The errand was delivered."
    match = regex.search(text)
    assert match is None, "Embedded 'err' in 'errand' should not match."

    text2 = "The failureful process did not trigger any alerts."
    match2 = regex.search(text2)
    assert match2 is None, "Embedded negative term with extra suffix should not match."


# Test that multiple occurrences in a string are correctly identified.
def test_multiple_occurrences():
    text = "error, timeout, and crash all occurred during the process."
    matches = regex.findall(text)
    # Check that each expected keyword is found at least once.
    expected_keywords = ["error", "timeout", "crash"]
    for keyword in expected_keywords:
        assert any(
            keyword.lower() == m.lower() for m in matches
        ), f"Expected to find '{keyword}' in matches."


# Test that words with punctuation at boundaries match correctly.
def test_no_false_positive_at_boundaries():
    text = "The system reports a 'failure.' but not a failureless scenario."
    # The regex should match "failure" in "failure." (due to the word boundary before the punctuation)
    match = regex.search(text)
    assert (
        match is not None
    ), "Expected a match for 'failure' with trailing punctuation."
    assert (
        match.group(0).lower() == "failure"
    ), f"Expected 'failure', got {match.group(0)}"
