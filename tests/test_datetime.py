import pytest
import argparse
import datetime as dt
from klp import guess_datetime, timedelta_from, add_ts_delta


@pytest.fixture
def mock_args():
    """Create a mock args object with default values."""
    args = argparse.Namespace()
    args.debug = False
    args.localtime = False
    args.utc = True
    args.ts_key = None
    args.error_handling = "ignore"
    return args


def test_timedelta_from_valid():
    """Test parsing of valid time intervals."""
    assert timedelta_from("1h") == dt.timedelta(hours=1)
    assert timedelta_from("30m") == dt.timedelta(minutes=30)
    assert timedelta_from("1.5h") == dt.timedelta(hours=1, minutes=30)
    assert timedelta_from("90s") == dt.timedelta(seconds=90)


def test_timedelta_from_invalid():
    """Test parsing of invalid time intervals."""
    with pytest.raises(argparse.ArgumentTypeError, match="Invalid timespec: invalid"):
        timedelta_from("invalid")

    with pytest.raises(
        argparse.ArgumentTypeError, match="Durations cannot be negative"
    ):
        timedelta_from("-1h")


def test_add_ts_delta(mock_args):
    """Test timestamp delta calculations."""
    import sys

    sys.modules["klp"].args = mock_args

    event1 = {"timestamp": "2024-03-16T14:30:00Z"}
    event2 = {"timestamp": "2024-03-16T14:30:01Z"}
    event3 = {"timestamp": "2024-03-16T14:31:00Z"}

    # First event should get delta from epoch
    result1, last_ts = add_ts_delta(event1, None)
    assert "_klp_timedelta" in result1

    # One second difference
    result2, last_ts = add_ts_delta(event2, last_ts)
    assert result2["_klp_timedelta"] == "0:00:01.000000"

    # One minute difference
    result3, last_ts = add_ts_delta(event3, last_ts)
    assert result3["_klp_timedelta"] == "0:00:59.000000"

    # Invalid timestamp
    invalid_event = {"timestamp": "invalid"}
    result_invalid, last_ts = add_ts_delta(invalid_event, last_ts)
    assert "_klp_timedelta" not in result_invalid


def test_guess_datetime_formats():
    """Test datetime parsing from various formats."""

    # Convert to UTC for consistent comparison
    def to_utc(dt_obj):
        if dt_obj is None:
            return None
        return dt_obj.astimezone(dt.timezone.utc)

    test_cases = [
        # ISO format with timezone
        (
            "2024-03-16T14:30:00Z",
            dt.datetime(2024, 3, 16, 14, 30, tzinfo=dt.timezone.utc),
        ),
        (
            "2024-03-16T14:30:00+00:00",
            dt.datetime(2024, 3, 16, 14, 30, tzinfo=dt.timezone.utc),
        ),
        # Dates with timezone info
        (
            "2024-03-16 14:30:00Z",
            dt.datetime(2024, 3, 16, 14, 30, tzinfo=dt.timezone.utc),
        ),
        (
            "2024-03-16 14:30:00+00:00",
            dt.datetime(2024, 3, 16, 14, 30, tzinfo=dt.timezone.utc),
        ),
        # Date only formats (these will be interpreted in local time)
        (
            "2024-03-16",
            dt.datetime(2024, 3, 16, 0, 0).astimezone().astimezone(dt.timezone.utc),
        ),
        (
            "2024-03",
            dt.datetime(2024, 3, 1, 0, 0).astimezone().astimezone(dt.timezone.utc),
        ),
        # Common Log Format
        (
            "16/Mar/2024:14:30:00 +0000",
            dt.datetime(2024, 3, 16, 14, 30, tzinfo=dt.timezone.utc),
        ),
        # Invalid formats
        ("invalid", None),
        ("", None),
    ]

    for input_str, expected in test_cases:
        result = guess_datetime(input_str)
        if expected is None:
            assert result is None, f"Expected None for input {input_str}, got {result}"
        else:
            result = to_utc(result)
            assert abs(result - expected) < dt.timedelta(
                seconds=1
            ), f"Failed for input {input_str}: got {result}, expected {expected}"
