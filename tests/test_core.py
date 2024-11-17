import pytest
from klp import (
    parse_kv,
    split_startswith,
    split_endswith,
    extract_blocks,
    extract_json,
    make_greppable,
    sanitize_key,
)


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


def test_extract_json():
    """Test JSON extraction from text."""
    # Basic JSON object
    text = 'before {"key": "value"} after'
    assert extract_json(text) == '{"key": "value"}'

    # Test invalid JSON
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
