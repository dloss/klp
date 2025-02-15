import re

from klp import BUILTIN_REGEXES


DURATION_PATTERNS = BUILTIN_REGEXES["duration"]


def is_duration(text: str) -> bool:
    """Check if text contains a valid duration token."""
    return any(re.search(pattern, text) is not None for pattern in DURATION_PATTERNS)


# Tests (unverändert):
def test_basic_units():
    """Test basic time units with whole numbers."""
    assert is_duration("500ms")
    assert is_duration("30s")
    assert is_duration("5m")
    assert is_duration("2h")
    assert not is_duration("3d")  # Should not match
    assert not is_duration("4w")  # Should not match


def test_decimal_values():
    """Test decimal values with units."""
    assert is_duration("1.5s")
    assert is_duration("0.5h")
    assert is_duration("2.75m")
    assert is_duration("0.001ms")
    assert not is_duration(".5")  # No unit
    assert not is_duration("1.5")  # No unit


def test_microseconds():
    """Test microsecond formats."""
    assert is_duration("500us")
    assert is_duration("500μs")
    assert is_duration("500µs")
    assert is_duration("0.5us")
    assert not is_duration("us")
    assert not is_duration("500u")


def test_written_units():
    """Test fully written time units."""
    assert is_duration("1 minute")
    assert is_duration("2 minutes")
    assert is_duration("1 hour")
    assert is_duration("2 hours")
    assert is_duration("1 day")
    assert is_duration("2 days")
    assert is_duration("1 week")
    assert is_duration("2 weeks")
    assert is_duration("1 month")
    assert is_duration("2 months")
    assert is_duration("1 year")
    assert is_duration("2 years")
    assert is_duration("1.5 hours")
    assert not is_duration("minute")
    assert not is_duration("hours")


def test_written_units_no_space():
    """Test written units without spaces."""
    assert is_duration("1minute")
    assert is_duration("2minutes")
    assert is_duration("1hour")
    assert is_duration("2hours")
    assert is_duration("1.5hours")


def test_combined_units():
    """Test combinations of units."""
    assert is_duration("1h30m")
    assert is_duration("1m30s")
    assert is_duration("1h30m15s")
    assert is_duration("1h15s")  # Hour + seconds
    assert not is_duration("1h30")  # Incomplete
    assert not is_duration("1d30m")  # No 'd' in combinations
    assert not is_duration("30m1h")  # Wrong order
    assert not is_duration("1h30m5")  # Missing final unit


def test_context():
    """Test durations in context."""
    assert is_duration("Completed in 500ms")
    assert is_duration("Took 1.5 hours to complete")
    assert is_duration("Duration: 2h30m")


def test_edge_cases():
    """Test edge cases and potential false positives."""
    assert not is_duration("")
    assert not is_duration("ms")
    assert not is_duration("hour")
    assert not is_duration("1")
    assert not is_duration("1.5")
    assert not is_duration("500")
    assert not is_duration("1.5.0s")  # Invalid number format
    assert not is_duration("1hrs")  # Invalid unit combination
    assert not is_duration("millis")  # Not a valid unit
    assert not is_duration("micros")  # Not a valid unit
    assert not is_duration("1.h")  # Invalid number format
    assert not is_duration("1..5h")  # Invalid number format


def test_invalid_combinations():
    """Test invalid unit combinations and formats."""
    assert not is_duration("1h2d")  # Invalid combination
    assert not is_duration("1m2months")  # Mixed short/long
    assert not is_duration("1hour30")  # Incomplete combination
    assert not is_duration("hour1")  # Wrong order
    assert not is_duration("1 h 30 m")  # Spaces in combination
