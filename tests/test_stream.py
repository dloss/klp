import os
import json
import subprocess
import time
from datetime import datetime


# Helper to get paths relative to repo root
def get_repo_path(*paths):
    """Get absolute path relative to current test directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", *paths))


KLP_PATH = get_repo_path("klp.py")
GENERATE_STREAM_PATH = get_repo_path("tools/generate_stream.py")


def run_pipeline(generator_args=None, klp_args=None, duration=0.2):
    """
    Run a pipeline of generate_stream.py | klp.py with given arguments.

    Args:
        generator_args: List of arguments for generate_stream.py
        klp_args: List of arguments for klp.py
        duration: How long to let the pipeline run (seconds)

    Returns:
        tuple: (stdout lines, stderr lines)
    """
    # Ensure scripts are executable
    os.chmod(GENERATE_STREAM_PATH, 0o755)
    os.chmod(KLP_PATH, 0o755)

    # Start generator process
    generator_cmd = [GENERATE_STREAM_PATH]
    if generator_args:
        generator_cmd.extend(generator_args)

    generator = subprocess.Popen(
        generator_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    # Start klp process
    klp_cmd = [KLP_PATH]
    if klp_args:
        klp_cmd.extend(klp_args)

    klp = subprocess.Popen(
        klp_cmd,
        stdin=generator.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Add these lines after starting klp process
    generator.stdout.flush()  # Force flush the generator output
    time.sleep(0.1)  # Give processes time to start up

    # Let it run
    time.sleep(duration)

    # Add a small delay before cleanup
    time.sleep(0.1)

    # Clean kill of generator will cause klp to exit when stdin closes
    generator.terminate()
    generator.wait()
    stdout, stderr = klp.communicate(timeout=2)

    return stdout.splitlines(), stderr.splitlines()


def test_basic_streaming():
    """Test basic log streaming functionality."""
    stdout, stderr = run_pipeline(duration=0.2)

    # Should get roughly 0.2 seconds worth of logs (1 per second)
    assert 1 <= len(stdout) <= 3  # Allow some variance

    # Each line should be properly formatted
    for line in stdout:
        # Basic format checks
        assert "time=" in line
        assert "level=" in line
        assert "message=" in line


def test_streaming_jsonl_output():
    """Test JSON Lines output format."""
    stdout, stderr = run_pipeline(klp_args=["--output-format=jsonl"], duration=0.2)

    # Verify each line is valid JSON
    for line in stdout:
        entry = json.loads(line)
        assert isinstance(entry, dict)
        assert "time" in entry
        assert "level" in entry
        assert "message" in entry

        # Verify timestamp format
        time_str = entry["time"].rstrip("Z")
        assert datetime.fromisoformat(time_str)  # Should not raise exception


def test_streaming_with_grep():
    """Test grepping from stream."""
    stdout, stderr = run_pipeline(
        klp_args=["--grep=error", "--output-format=jsonl"],
        duration=0.4,  # Longer duration to ensure we get some errors
    )

    # Every line should contain 'error'
    for line in stdout:
        entry = json.loads(line)
        assert "error" in line.lower()
        # Should be in level field specifically
        assert entry["level"] == "error"


def test_streaming_with_key_selection():
    """Test selecting specific keys from stream."""
    stdout, stderr = run_pipeline(
        klp_args=["-k", "time,level,message", "--output-format=jsonl"], duration=0.2
    )

    # Verify only requested fields are present
    for line in stdout:
        entry = json.loads(line)
        assert set(entry.keys()) == {"time", "level", "message"}


def test_streaming_stats():
    """Test statistics generation from stream."""
    stdout, stderr = run_pipeline(klp_args=["--stats-only"], duration=0.3)

    # Stats should be written to stderr
    assert len(stderr) > 0
    stats_text = "\n".join(stderr)

    # Basic stats checks
    assert "Events shown:" in stats_text
    assert "Time span shown:" in stats_text
    assert "Keys seen:" in stats_text
    assert "Log levels seen:" in stats_text


def test_streaming_levelmap():
    """Test level map visualization."""
    stdout, stderr = run_pipeline(klp_args=["--levelmap"], duration=0.3)

    # Should get a character map of log levels
    assert len(stdout) > 0
    levelmap = "".join(stdout)

    # Should contain first letters of log levels
    assert any(c in levelmap for c in "diwef")  # debug, info, warn, error, fatal


def test_streaming_with_time_window():
    """Test time windowed streaming."""
    stdout, stderr = run_pipeline(
        klp_args=["--output-format=jsonl", "--duration=1s"], duration=0.3
    )

    if stdout:  # If we got any output
        # Parse timestamps
        times = []
        for line in stdout:
            entry = json.loads(line)
            time_str = entry["time"].rstrip("Z")
            times.append(datetime.fromisoformat(time_str))

        # Verify time window
        if len(times) >= 2:
            time_span = max(times) - min(times)
            assert time_span.total_seconds() <= 1.5  # Allow some slack


def test_error_handling():
    """Test handling of malformed input."""
    # Run klp with invalid input
    process = subprocess.Popen(
        [KLP_PATH],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Send some invalid logfmt
    stdout, stderr = process.communicate("this is not valid logfmt\n")

    # Should handle invalid input gracefully
    assert process.returncode == 0  # Shouldn't crash
