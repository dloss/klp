import pytest
import argparse
from klp import flatten_object, reorder


@pytest.fixture
def mock_args():
    """Create a mock args object with default values."""
    args = argparse.Namespace()
    args.debug = False
    args.keys = []
    args.keys_not = []
    return args


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
