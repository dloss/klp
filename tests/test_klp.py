# tests/test_klp.py
import pytest
import datetime
import argparse
from klp import (
    parse_logfmt,
    parse_jsonl,
    guess_datetime,
    timedelta_from,
    extract_json,
    make_greppable,
    sanitize_key,
)


def test_parse_logfmt():
    """Test parsing of logfmt formatted strings."""
    text = 'timestamp="2024-03-16T14:30:00Z" level=info msg="Starting service"'
    expected = {
        "timestamp": "2024-03-16T14:30:00Z",
        "level": "info",
        "msg": "Starting service",
    }
    assert parse_logfmt(text) == expected


def test_parse_jsonl():
    """Test parsing of JSONL formatted strings."""
    text = '{"timestamp": "2024-03-16T14:30:00Z", "level": "info", "msg": "Test"}'
    expected = {"timestamp": "2024-03-16T14:30:00Z", "level": "info", "msg": "Test"}
    assert parse_jsonl(text) == expected


def test_guess_datetime():
    """Test datetime parsing from various formats."""
    assert guess_datetime("2024-03-16T14:30:00Z") is not None
    assert guess_datetime("invalid") is None


def test_timedelta_from_valid():
    """Test parsing of valid time intervals."""
    assert timedelta_from("1h") == datetime.timedelta(hours=1)
    assert timedelta_from("30m") == datetime.timedelta(minutes=30)
    assert timedelta_from("1.5h") == datetime.timedelta(hours=1, minutes=30)
    assert timedelta_from("90s") == datetime.timedelta(seconds=90)


def test_timedelta_from_invalid():
    """Test parsing of invalid time intervals."""
    with pytest.raises(argparse.ArgumentTypeError, match="Invalid timespec: invalid"):
        timedelta_from("invalid")

    with pytest.raises(
        argparse.ArgumentTypeError, match="Durations cannot be negative"
    ):
        timedelta_from("-1h")


def test_extract_json():
    """Test JSON extraction from text."""
    text = 'before {"key": "value"} after'
    assert extract_json(text) == '{"key": "value"}'

    with pytest.raises(ValueError):
        extract_json("invalid")


def test_make_greppable():
    """Test creation of greppable string from event dict."""
    event = {"key1": "value1", "key2": "value2"}
    expected = 'key1="value1" key2="value2"'
    assert make_greppable(event) == expected


def test_sanitize_key():
    """Test sanitization of keys."""
    assert sanitize_key("user.name@domain") == "user_name_domain"
    assert sanitize_key("valid_key_123") == "valid_key_123"
