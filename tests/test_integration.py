import subprocess
import json
import os
import pytest

# Helper to get paths relative to git repo root
def get_repo_path(*paths):
    """Get absolute path relative to current test directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', *paths))

# Get path to klp.py in repo root
KLP_PATH = get_repo_path('klp.py')

@pytest.fixture
def temp_logfile(tmp_path):
    """Create a temporary logfile with test data."""
    logfile = tmp_path / "test.log"
    with open(logfile, "w") as f:
        f.write('timestamp="2024-03-16T10:00:00Z" level=info message="Test message 1"\n')
        f.write('timestamp="2024-03-16T10:01:00Z" level=error message="Test error"\n')
        f.write('timestamp="2024-03-16T10:02:00Z" level=info message="Test message 2"\n')
    return str(logfile)

@pytest.fixture
def temp_jsonfile(tmp_path):
    """Create a temporary JSON file with test data."""
    jsonfile = tmp_path / "test.json"
    data = [
        {"timestamp": "2024-03-16T10:00:00Z", "level": "info", "message": "Test message"},
        {"timestamp": "2024-03-16T10:01:00Z", "level": "error", "message": "Test error"}
    ]
    with open(jsonfile, "w") as f:
        json.dump(data, f)
    return str(jsonfile)

@pytest.fixture
def temp_csvfile(tmp_path):
    """Create a temporary CSV file with test data."""
    csvfile = tmp_path / "test.csv"
    with open(csvfile, "w") as f:
        f.write("timestamp,level,message\n")
        f.write("2024-03-16T10:00:00Z,info,Test message\n")
        f.write("2024-03-16T10:01:00Z,error,Test error\n")
    return str(csvfile)

def test_basic_logfmt_processing(temp_logfile):
    """Test basic logfmt file processing."""
    cmd = ["python", KLP_PATH, "--output-format=jsonl", temp_logfile]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Process failed with error: {result.stderr}"

    # Parse output lines as JSON
    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 3
    assert outputs[0]["level"] == "info"
    assert outputs[1]["level"] == "error"
    assert outputs[2]["level"] == "info"

def test_json_processing(temp_jsonfile):
    """Test JSON file processing."""
    cmd = [
        "python",
        KLP_PATH,
        "--input-format=json",
        "--output-format=jsonl",
        temp_jsonfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Process failed with error: {result.stderr}"

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 2
    assert outputs[0]["level"] == "info"
    assert outputs[1]["level"] == "error"

def test_csv_processing(temp_csvfile):
    """Test CSV file processing."""
    cmd = [
        "python",
        KLP_PATH,
        "--input-format=csv",
        "--output-format=jsonl",
        temp_csvfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Process failed with error: {result.stderr}"

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 2
    assert "timestamp" in outputs[0]
    assert "level" in outputs[0]
    assert "message" in outputs[0]

def test_grep_functionality(temp_logfile):
    """Test grep functionality."""
    cmd = [
        "python",
        KLP_PATH,
        "--output-format=jsonl",
        "--grep=error",
        temp_logfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Process failed with error: {result.stderr}"

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 1
    assert outputs[0]["level"] == "error"

def test_timestamp_filtering(temp_logfile):
    """Test timestamp-based filtering."""
    cmd = [
        "python",
        KLP_PATH,
        "--output-format=jsonl",
        "--from=2024-03-16T10:01:00Z",
        temp_logfile,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, f"Process failed with error: {result.stderr}"

    outputs = [json.loads(line) for line in result.stdout.strip().split("\n")]
    assert len(outputs) == 2
    assert outputs[0]["timestamp"] >= "2024-03-16T10:01:00Z"
