# tests/conftest.py
import os
import pytest
import tempfile
import json


@pytest.fixture
def temp_logfile():
    """Create a temporary logfile with sample logfmt data."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write(
            'timestamp="2024-03-16T14:30:00Z" level=info msg="Starting service" service=api\n'
        )
        f.write(
            'timestamp="2024-03-16T14:30:01Z" level=error msg="Connection failed" service=db\n'
        )
        f.write(
            'timestamp="2024-03-16T14:30:02Z" level=info msg="Reconnected" service=db\n'
        )
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_jsonfile():
    """Create a temporary JSON file with sample data."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        data = [
            {
                "timestamp": "2024-03-16T14:30:00Z",
                "level": "info",
                "msg": "Test message",
            },
            {
                "timestamp": "2024-03-16T14:30:01Z",
                "level": "error",
                "msg": "Error message",
            },
        ]
        json.dump(data, f)
    yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_csvfile():
    """Create a temporary CSV file with sample data."""
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("timestamp,level,message\n")
        f.write("2024-03-16T14:30:00Z,info,Test message\n")
        f.write("2024-03-16T14:30:01Z,error,Error message\n")
    yield f.name
    os.unlink(f.name)
