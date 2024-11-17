# tests/test_time.py
import pytest
import argparse
import datetime as dt
from klp import guess_datetime, format_datetime, timedelta_from, add_ts_delta


@pytest.fixture
def mock_args():
    args = argparse.Namespace()
    args.debug = False
    args.localtime = False
    args.utc = True
    args.ts_key = None
    return args


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
