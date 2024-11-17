import pytest
import argparse
import datetime as dt
from klp import (
    visible,
    matches_python_expr,
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
    args.grep = []
    args.grep_not = []
    args.grep_by_key = {}
    args.grep_not_by_key = {}
    args.where = ""
    args.loglevels = None
    args.loglevels_not = None
    args.from_dt = None
    args.to_dt = None
    args.files = []  # Add default empty list of files
    args.files = []  # Added this line
    return args


@pytest.fixture
def sample_event():
    return {
        "timestamp": "2024-03-16T14:30:00Z",
        "level": "error",
        "message": "Test error message",
        "service": "api",
    }


def test_visible_with_grep(mock_args, sample_event):
    """Test grep filtering functionality."""
    import sys

    sys.modules["klp"].args = mock_args

    # Setup grep patterns
    import re

    mock_args.grep = [re.compile(r"error")]
    mock_args.grep_not = [re.compile(r"success")]

    # Should match error pattern
    assert visible(sample_event) is True

    # Should not match when error is removed
    sample_event["message"] = "Test success message"
    assert visible(sample_event) is False

    # Should not match when blocked pattern is present
    sample_event["message"] = "Error with success"
    assert visible(sample_event) is False


def test_visible_with_time_bounds(mock_args, sample_event):
    """Test time-based filtering."""
    import sys

    sys.modules["klp"].args = mock_args

    # Setup time bounds
    mock_args.from_dt = dt.datetime(2024, 3, 16, 14, 0, 0, tzinfo=dt.timezone.utc)
    mock_args.to_dt = dt.datetime(2024, 3, 16, 15, 0, 0, tzinfo=dt.timezone.utc)

    # Event within bounds
    assert visible(sample_event) is True

    # Event before lower bound
    sample_event["timestamp"] = "2024-03-16T13:59:59Z"
    assert visible(sample_event) is False

    # Event after upper bound
    sample_event["timestamp"] = "2024-03-16T15:00:01Z"
    # Add a second file to prevent StoppedEarly
    mock_args.files = ["file1.log", "file2.log"]
    assert visible(sample_event) is False

    # Invalid timestamp
    sample_event["timestamp"] = "invalid"
    assert visible(sample_event) is True  # Should not filter out invalid timestamps


def test_visible_with_log_levels(mock_args, sample_event):
    """Test log level filtering."""
    import sys

    sys.modules["klp"].args = mock_args

    # Include only specific levels
    mock_args.loglevels = ["error", "warning"]
    assert visible(sample_event) is True

    sample_event["level"] = "info"
    assert visible(sample_event) is False

    # Exclude specific levels
    mock_args.loglevels = None
    mock_args.loglevels_not = ["debug", "info"]
    sample_event["level"] = "error"
    assert visible(sample_event) is True

    sample_event["level"] = "info"
    assert visible(sample_event) is False


def test_visible_with_key_grep(mock_args, sample_event):
    """Test key-specific grep patterns."""
    import sys

    sys.modules["klp"].args = mock_args

    import re

    mock_args.grep_by_key = {"level": re.compile(r"error|warning")}
    assert visible(sample_event) is True

    sample_event["level"] = "info"
    assert visible(sample_event) is False

    # Test negative patterns
    mock_args.grep_by_key = {}
    mock_args.grep_not_by_key = {"service": re.compile(r"database")}
    assert visible(sample_event) is True

    sample_event["service"] = "database"
    assert visible(sample_event) is False


def test_matches_python_expr(mock_args):
    """Test Python expression matching against events."""
    # Set the args directly in the klp.globals() namespace
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
