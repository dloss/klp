from klp import (
    parse_logfmt,
    parse_jsonl,
    parse_clf,
    parse_combined,
    parse_log4j,
    parse_unix,
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


def test_parse_clf():
    """Test Common Log Format parsing."""
    # Standard line
    line = '127.0.0.1 - frank [16/Mar/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234'
    result = parse_clf(line)
    assert result["host"] == "127.0.0.1"
    assert result["ident"] == "-"
    assert result["user"] == "frank"
    assert result["time"] == "16/Mar/2024:14:30:00 +0000"
    assert result["request"] == "GET /index.html HTTP/1.1"
    assert result["status"] == "200"
    assert result["size"] == "1234"

    # With missing fields using "-"
    line = '127.0.0.1 - - [16/Mar/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 -'
    result = parse_clf(line)
    assert result["size"] == "0"  # Dash is converted to 0

    # Invalid format
    assert parse_clf("Invalid line") == {}


def test_parse_combined():
    """Test Combined Log Format parsing with various cases."""
    # Looking at RE_COMBINED in klp.py, the regex matches these field names

    # Standard line
    line = '127.0.0.1 - frank [16/Mar/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"'
    result = parse_combined(line)
    assert result["host"] == "127.0.0.1"
    assert result["ident"] == "-"
    assert result["user"] == "frank"
    assert result["time"] == "16/Mar/2024:14:30:00 +0000"
    assert result["request"] == "GET /index.html HTTP/1.1"
    assert result["status"] == "200"
    assert result["size"] == "1234"
    assert result["referrer"] == "http://example.com"
    assert result["agent"] == "Mozilla/5.0"

    # With missing fields using "-"
    line = '127.0.0.1 - - [16/Mar/2024:14:30:00 +0000] "GET /index.html HTTP/1.1" 200 - "-" "-"'
    result = parse_combined(line)
    assert result["ident"] == "-"
    assert result["user"] == "-"
    assert result["size"] == "0"  # Dash is converted to 0
    assert result["referrer"] == "-"
    assert result["agent"] == "-"

    # Invalid format
    assert parse_combined("Invalid line") == {}


def test_parse_log4j():
    """Test Log4j format parsing with various cases."""
    # Standard line
    line = "2024-01-19 15:04:23,456 [main] INFO [com.example.Service] - Started successfully"
    result = parse_log4j(line)
    assert result["timestamp"] == "2024-01-19 15:04:23,456"
    assert result["thread"] == "main"
    assert result["level"] == "INFO"
    assert result["logger"] == "com.example.Service"
    assert result["message"] == "Started successfully"

    # Different timestamp format
    line = "19-Jan-2024 15:04:23.456 [main] ERROR [com.example] - Failed to start"
    result = parse_log4j(line)
    assert result["timestamp"] == "19-Jan-2024 15:04:23.456"
    assert result["level"] == "ERROR"

    # Complex thread name
    line = "2024-01-19 15:04:23,456 [http-nio-8080-exec-1] DEBUG [com.example] - Processing request"
    result = parse_log4j(line)
    assert result["thread"] == "http-nio-8080-exec-1"
    assert result["level"] == "DEBUG"

    # Complex logger name with version
    line = (
        "2024-01-19 15:04:23,456 [main] INFO [com.example.v2.api.Service] - API ready"
    )
    result = parse_log4j(line)
    assert result["logger"] == "com.example.v2.api.Service"

    # Message with special characters
    line = '2024-01-19 15:04:23,456 [main] WARN [com.example] - User "john.doe" failed auth: error=Invalid credentials'
    result = parse_log4j(line)
    assert result["message"] == 'User "john.doe" failed auth: error=Invalid credentials'

    # With extra whitespace
    line = (
        "  2024-01-19 15:04:23,456  [main]   INFO   [com.example]  -   Extra spaces  "
    )
    result = parse_log4j(line)
    assert result["message"] == "Extra spaces"

    # Invalid format
    assert parse_log4j("Invalid line") == {}


def test_parse_unix():
    """Test Unix syslog format parsing."""
    # Standard format with PID
    line = "Mar 16 14:30:00 localhost sshd[12345]: Connection accepted"
    result = parse_unix(line)
    assert result["timestamp"] == "Mar 16 14:30:00"
    assert result["hostname"] == "localhost"
    assert result["service"] == "sshd"
    assert result["pid"] == "12345"
    assert result["message"] == "Connection accepted"

    # Without PID
    line = "Mar 16 14:30:00 localhost sshd: Connection accepted"
    result = parse_unix(line)
    assert "pid" not in result
    assert result["service"] == "sshd"
    assert result["message"] == "Connection accepted"

    # Invalid format
    assert parse_unix("Invalid line") == {}


def test_parse_logfmt_basic():
    text = "key1=value1 key2=value2"
    expected = {"key1": "value1", "key2": "value2"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_spaces():
    text = 'key1="value with spaces" key2=value2'
    expected = {"key1": "value with spaces", "key2": "value2"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_escaped_quotes():
    text = 'key1="value with \\"escaped quotes\\"" key2=value2'
    expected = {"key1": 'value with "escaped quotes"', "key2": "value2"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_quotes_inside():
    text = 'key1=singlequote\'s key2=double"quot"es'
    expected = {"key1": "singlequote's", "key2": 'double"quot"es'}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_unicode():
    text = 'schlüssel=Schloß kauf="Äpfel aus Köln"'
    expected = {"schlüssel": "Schloß", "kauf": "Äpfel aus Köln"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_dots_in_key():
    text = "my.long.key=value1 key2=value2"
    expected = {"my.long.key": "value1", "key2": "value2"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_with_equal_in_val():
    text = "key=2+2=4 key2=test"
    expected = {"key": "2+2=4", "key2": "test"}
    assert parse_logfmt(text) == expected


def test_parse_logfmt_empty_string():
    assert parse_logfmt("") == {}
