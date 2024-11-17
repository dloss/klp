# tests/test_parsing.py
from klp import parse_unix, parse_combined, parse_clf


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
