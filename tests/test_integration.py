# tests/test_integration.py
import subprocess
import json


def test_basic_logfmt_processing(temp_logfile):
    """Test basic logfmt file processing."""
    cmd = ["python", "klp.py", "--output-format=jsonl", temp_logfile]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0

    # Parse output lines as JSON
    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 3
    assert outputs[0]["level"] == "info"
    assert outputs[1]["level"] == "error"


def test_json_processing(temp_jsonfile):
    """Test JSON file processing."""
    cmd = [
        "python",
        "klp.py",
        "--input-format=json",
        "--output-format=jsonl",
        temp_jsonfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 2
    assert outputs[0]["level"] == "info"
    assert outputs[1]["level"] == "error"


def test_csv_processing(temp_csvfile):
    """Test CSV file processing."""
    cmd = [
        "python",
        "klp.py",
        "--input-format=csv",
        "--output-format=jsonl",
        temp_csvfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 2
    assert "timestamp" in outputs[0]
    assert "level" in outputs[0]
    assert "message" in outputs[0]
