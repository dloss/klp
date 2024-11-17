# tests/test_complex.py
import pytest
import argparse
import datetime as dt
from klp import (
    parse_kv,
    split_startswith,
    split_endswith,
    extract_blocks,
    flatten_object,
    reorder,
    matches_python_expr,
    parse_clf,
    parse_combined,
    add_ts_delta,
    guess_datetime,
)


@pytest.fixture
def mock_args():
    """Create a mock args object with default values."""
    args = argparse.Namespace()
    args.debug = False
    args.debug_where = False
    args.ts_key = None
    args.keys = []
    args.keys_not = []
    return args


def test_matches_python_expr(mock_args):
    """Test Python expression matching against events."""
    # Set the args directly in the klp.globals() namespace
    import klp
    import sys

    sys.modules["klp"].args = mock_args

    event = {
        "level": "ERROR",
        "status": 500,
        "message": "Test failed",
        "timestamp": "2024-03-16T14:30:00Z",
    }

    # Basic comparisons
    assert matches_python_expr("level == 'ERROR'", event) is True
    assert matches_python_expr("status >= 500", event) is True
    assert matches_python_expr("'failed' in message", event) is True

    # Complex expressions
    assert matches_python_expr("level == 'ERROR' and status >= 500", event) is True
    assert matches_python_expr("len(message) > 5 and 'Test' in message", event) is True

    # Using imported functions
    assert matches_python_expr("'2024' in timestamp", event) is True

    # Invalid expressions
    assert matches_python_expr("invalid_variable", event) is False
    assert matches_python_expr("nonexistent.function()", event) is False


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


def test_reorder(mock_args):
    """Test event key reordering."""
    import sys

    event = {
        "timestamp": "2024-03-16T14:30:00Z",
        "level": "ERROR",
        "message": "Test message",
        "extra": "data",
    }

    # Test with specific keys
    mock_args.keys = ["message", "level"]
    mock_args.keys_not = []
    sys.modules["klp"].args = mock_args
    result = reorder(event)
    assert list(result.keys()) == ["message", "level"]

    # Test with excluded keys
    mock_args.keys = []
    mock_args.keys_not = ["extra"]
    sys.modules["klp"].args = mock_args
    result = reorder(event)
    assert "extra" not in result
    assert all(k in result for k in ["timestamp", "level", "message"])

    # Test with no specifications
    mock_args.keys = []
    mock_args.keys_not = []
    sys.modules["klp"].args = mock_args
    result = reorder(event)
    assert result == event


def test_parse_kv_complex():
    """Test key-value parsing with different separators and formats."""
    # Basic case
    assert parse_kv("key1=val1 key2=val2") == {"key1": "val1", "key2": "val2"}

    # Custom separators
    assert parse_kv("key1:val1;key2:val2", sep=";", kvsep=":") == {
        "key1": "val1",
        "key2": "val2",
    }

    # Handle missing values
    assert parse_kv("key1=val1 key2= key3=val3") == {
        "key1": "val1",
        "key2": "",
        "key3": "val3",
    }

    # Handle equals in values
    assert parse_kv("key1=val=1 key2=val2") == {"key1": "val=1", "key2": "val2"}

    # Note: parse_kv splits on whitespace by default
    assert parse_kv("key1=val1 value key2=val2") == {"key1": "val1", "key2": "val2"}


def test_split_startswith():
    """Test splitting strings on regex patterns."""
    # Basic split on newlines
    text = "First\\nSecond\\nThird"
    assert split_startswith(text, r"\\n") == ["First", "\\nSecond", "\\nThird"]

    # Empty pattern
    assert split_startswith("text", "") == ["text"]

    # No matches
    assert split_startswith("abc", "x") == ["abc"]

    # Multiple consecutive matches
    assert split_startswith("axbxcx", "x") == ["a", "xb", "xc", "x"]

    # Empty string
    assert split_startswith("", "x") == [""]


def test_flatten_object():
    """Test JSON object flattening with nested structures."""
    # Nested dictionaries
    nested = {"a": {"b": 1, "c": {"d": 2}}, "e": 3}
    assert flatten_object(nested) == {"a.b": 1, "a.c.d": 2, "e": 3}

    # Arrays
    with_arrays = {"a": [{"b": 1}, {"c": 2}], "d": 3}
    assert flatten_object(with_arrays) == {"a.0.b": 1, "a.1.c": 2, "d": 3}

    # Mixed nested structures
    mixed = {"a": [{"b": {"c": 1}}, 2], "d": {"e": [3, 4]}}
    assert flatten_object(mixed) == {"a.0.b.c": 1, "a.1": 2, "d.e.0": 3, "d.e.1": 4}


def test_parse_clf():
    """Test Common Log Format parsing."""
    valid_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326'
    result = parse_clf(valid_line)
    assert result["host"] == "127.0.0.1"
    assert result["user"] == "frank"
    assert result["time"] == "10/Oct/2000:13:55:36 -0700"
    assert result["request"] == "GET /apache_pb.gif HTTP/1.0"
    assert result["status"] == "200"
    assert result["size"] == "2326"

    # Test handling of "-" in size field
    line_with_dash = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 -'
    result = parse_clf(line_with_dash)
    assert result.get("size", "0") == "0"  # Using get() with default

    # Test invalid line
    invalid_line = "This is not a CLF line"
    assert parse_clf(invalid_line) == {}


def test_parse_combined():
    """Test Combined Log Format parsing."""
    valid_line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"'
    result = parse_combined(valid_line)
    assert result["host"] == "127.0.0.1"
    assert result["user"] == "frank"
    assert result["time"] == "10/Oct/2000:13:55:36 -0700"
    assert result["request"] == "GET /apache_pb.gif HTTP/1.0"
    assert result["status"] == "200"
    assert result["size"] == "2326"
    assert result["referrer"] == "http://www.example.com/start.html"
    assert result["agent"] == "Mozilla/4.08 [en] (Win98; I ;Nav)"

    # Test invalid line
    invalid_line = "This is not a Combined Log Format line"
    assert parse_combined(invalid_line) == {}


@pytest.mark.parametrize(
    "input_lines, start_after, start_with, stop_before, stop_with, expected_blocks",
    [
        # Basic block extraction
        (
            ["start", "content1", "content2", "end"],
            None,
            ["start"],
            None,
            ["end"],
            [(["start", "content1", "content2", "end"], 1, 4)],
        ),
        # Multiple blocks
        (
            ["start", "c1", "end", "start", "c2", "end"],
            None,
            ["start"],
            None,
            ["end"],
            [(["start", "c1", "end"], 1, 3), (["start", "c2", "end"], 4, 6)],
        ),
        # Start after pattern
        (
            ["before", "start", "content", "end"],
            ["before"],
            None,
            None,
            ["end"],
            [(["start", "content", "end"], 2, 4)],
        ),
    ],
)
def test_extract_blocks(
    input_lines, start_after, start_with, stop_before, stop_with, expected_blocks
):
    """Test block extraction with different patterns."""
    blocks = list(
        extract_blocks(
            iter(input_lines),
            start_after=start_after,
            start_with=start_with,
            stop_before=stop_before,
            stop_with=stop_with,
        )
    )
    assert blocks == expected_blocks
