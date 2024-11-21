import pytest
import re
from klp import (
    BUILTIN_REGEXES,
    EStr,
    escape_doublequotes_quoted,
    extract_blocks,
    extract_json,
    make_greppable,
    parse_kv,
    sanitize_key,
    split_startswith,
    unescape,
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


def test_builtin_regexes_compile():
    """Test that all builtin regex patterns compile successfully."""
    for name, regexes in BUILTIN_REGEXES.items():
        for regex in regexes:
            try:
                re.compile(regex)
            except re.error as e:
                pytest.fail(f"Regex compilation for {name} failed with error: {e.msg}")


def test_escape_doublequotes():
    """Test escaping text with double quotes."""
    text = 'a "string" with double quotes'
    expected = 'a \\"string\\" with double quotes'
    assert escape_doublequotes_quoted(text) == expected


def test_escape_single_quotes():
    """Test escaping text with single quotes."""
    text = "a 'string' with single quotes"
    expected = "a 'string' with single quotes"
    assert escape_doublequotes_quoted(text) == expected


def test_escape_sequences():
    """Test escaping special characters."""
    text = "Escape seqs: \x00\t\n"
    expected = "Escape seqs: \\x00\\t\\n"
    assert escape_doublequotes_quoted(text) == expected


def test_unescape():
    """Test unescaping various escaped sequences."""
    assert unescape(r"This is a \"test\" string") == 'This is a "test" string'
    assert unescape(r"Escape sequences: \n \t") == "Escape sequences: \n \t"
    assert unescape("значение со spaces") == "значение со spaces"
    assert unescape("\\x01") == "\x01"


def test_extract_json_valid_object():
    """Test extracting valid JSON objects."""
    assert extract_json('{"name": "John", "age": 30}') == '{"name": "John", "age": 30}'
    assert extract_json("[1, 2, 3, 4]") == "[1, 2, 3, 4]"
    assert (
        extract_json('{"person": {"name": "John", "age": 30}, "city": "New York"}')
        == '{"person": {"name": "John", "age": 30}, "city": "New York"}'
    )


def test_extract_json_with_surrounding_text():
    """Test extracting JSON from text with non-JSON content."""
    assert (
        extract_json('Hello world {"name": "John", "age": 30}')
        == '{"name": "John", "age": 30}'
    )
    assert (
        extract_json('{"name": "John", "age": 30} and more text')
        == '{"name": "John", "age": 30}'
    )


def test_extract_json_invalid():
    """Test extracting invalid JSON raises ValueError."""
    with pytest.raises(ValueError):
        extract_json('{"name": "John" "age": 30}')
    with pytest.raises(ValueError):
        extract_json("Just plain text")
    with pytest.raises(ValueError):
        extract_json("")


def test_extract_json_multiple():
    """Test extracting first JSON object when multiple are present."""
    assert extract_json('{"name": "John"} {"age": 30}') == '{"name": "John"}'


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


def test_estr_init():
    s = EStr("This is a test")
    assert s == "This is a test"


def test_estr_basic_ops():
    s = EStr("This is a test")
    assert str(s) == "This is a test"
    assert len(s) == 14
    assert s[0] == "T"
    assert s[1] == "h"
    assert s[2] == "i"


def test_estr_col():
    s = EStr("This is a test")
    assert s.col(0) == "This"
    assert s.col(1) == "is"
    assert s.col(2) == "a"
    assert s.col(3) == "test"
    assert s.col(4) == None


def test_estr_cols_basic():
    s = EStr("This is  a test  with 7 columns")
    assert s.cols() == ["This", "is", "a", "test", "with", "7", "columns"]
    assert s.cols(0, 3) == ["This", "test"]
    assert s.cols(0, -1, 2, 2) == ["This", "columns", "a", "a"]
    assert s.cols("0,3") == "This test"
    assert s.cols("1") == "is"
    assert s.cols(1) == "is"
    assert s.cols("14") == ""
    assert s.cols("1:3") == "is a"
    assert s.cols("-2,2,4:") == "7 a with 7 columns"


def test_estr_cols_with_separators():
    s = EStr("This|is a|test with|4 columns")
    assert s.cols("1:3", sep="|") == "is a test with"
    assert s.cols("-2,2,4:", sep="|", outsep=":") == "test with:test with"


def test_estr_cols_with_regex():
    s = EStr("This2334is7453a654test232with232regex")
    assert s.cols("1:5", sep=re.compile(r"\d+")) == "is a test with"


def test_extract_json_valid_json_object():
    assert extract_json('{"name": "John", "age": 30}') == '{"name": "John", "age": 30}'


def test_extract_json_valid_json_array():
    assert extract_json("[1, 2, 3, 4]") == "[1, 2, 3, 4]"


def test_extract_json_nested_json():
    assert (
        extract_json('{"person": {"name": "John", "age": 30}, "city": "New York"}')
        == '{"person": {"name": "John", "age": 30}, "city": "New York"}'
    )


def test_extract_json_json_with_text_before():
    assert (
        extract_json('Hello world {"name": "John", "age": 30}')
        == '{"name": "John", "age": 30}'
    )


def test_extract_json_json_with_text_after():
    assert (
        extract_json('{"name": "John", "age": 30} and more text')
        == '{"name": "John", "age": 30}'
    )


def test_extract_json_invalid_json():
    with pytest.raises(ValueError):
        extract_json('{"name": "John" "age": 30}')


def test_extract_json_no_json():
    with pytest.raises(ValueError):
        extract_json("Just a plain text without JSON")


def test_extract_json_multiple_json_objects():
    assert extract_json('{"name": "John"} {"age": 30}') == '{"name": "John"}'


def test_extract_json_empty_string():
    with pytest.raises(ValueError):
        extract_json("")
