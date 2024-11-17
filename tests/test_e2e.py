import os
import re
import pytest
import subprocess
from pathlib import Path


# Helper to get paths relative to repo root
def get_repo_path(*paths):
    """Get absolute path relative to current test directory."""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", *paths))


KLP_PATH = get_repo_path("klp.py")


@pytest.fixture
def sample_logfile(tmp_path):
    """Create a log file with predictable timestamps and levels."""
    logfile = tmp_path / "test.log"
    with open(logfile, "w") as f:
        # Normal sequence
        f.write('time="2024-03-16T10:00:00Z" level=info message="Starting service"\n')
        f.write(
            'time="2024-03-16T10:00:01Z" level=debug message="Initializing cache"\n'
        )
        f.write('time="2024-03-16T10:00:02Z" level=warn message="Cache slow"\n')
        # Gap of 5 minutes
        f.write('time="2024-03-16T10:05:00Z" level=error message="Connection lost"\n')
        f.write('time="2024-03-16T10:05:01Z" level=info message="Reconnecting"\n')
        # Rapid sequence
        f.write('time="2024-03-16T10:05:01.100Z" level=debug message="Attempt 1"\n')
        f.write('time="2024-03-16T10:05:01.200Z" level=debug message="Attempt 2"\n')
        f.write('time="2024-03-16T10:05:01.300Z" level=debug message="Attempt 3"\n')
        # Success after attempts
        f.write('time="2024-03-16T10:05:02Z" level=info message="Connected"\n')
    return str(logfile)


def run_klp(logfile, *args, color=False):
    """Run klp with given args and return output."""
    cmd = ["python", KLP_PATH]
    if not color:
        cmd.append("--no-color")  # Ensure consistent output for testing
    cmd.extend(args)
    cmd.append(logfile)

    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0
    return result.stdout, result.stderr


def test_levelmap(sample_logfile):
    """Test level map visualization."""
    stdout, stderr = run_klp(sample_logfile, "--levelmap")

    # Should show timestamp followed by level indicators
    # i(nfo) d(ebug) w(arn) e(rror) i(nfo) d d d i
    lines = stdout.splitlines()
    assert len(lines) == 1  # All in one line

    # Extract the levelmap part (after the timestamp)
    levelmap = lines[0].split(" ", 1)[1].strip()
    assert levelmap == "idweidddi"


def test_mark_gaps(sample_logfile):
    """Test gap marking between events."""
    stdout, stderr = run_klp(sample_logfile, "--mark-gaps=1m")
    stderr_lines = stderr.splitlines()

    # Find the gap marker line
    gap_lines = [line for line in stderr_lines if "time gap:" in line]
    assert len(gap_lines) > 0

    # The first gap should be around 4:58
    gap_text = gap_lines[0]
    assert "time gap: 0:04:58" in gap_text


def test_fuse(sample_logfile):
    """Test fusing of rapid events."""
    stdout, stderr = run_klp(sample_logfile, "--fuse=0.5s")
    lines = stdout.splitlines()

    # Find the rapid sequence
    attempt_lines = [l for l in lines if "Attempt" in l]
    # Should only show last attempt with prefix
    assert len(attempt_lines) == 1
    assert attempt_lines[0].startswith("5 ")
    assert "Attempt 3" in attempt_lines[0]


def test_fuse_with_gaps(sample_logfile):
    """Test fuse with gap marking."""
    stdout, stderr = run_klp(sample_logfile, "--fuse=0.5s", "--mark-gaps=1m")
    stdout_lines = stdout.splitlines()
    stderr_lines = stderr.splitlines()

    # Verify both gaps and fusing
    gap_lines = [l for l in stderr_lines if "time gap:" in l]
    fused_lines = [l for l in stdout_lines if l.startswith("5 ")]

    assert len(gap_lines) > 0  # Should have gap markers
    assert len(fused_lines) > 0  # Should have fused events


def test_each_key(sample_logfile):
    """Test printing each key on a separate line."""
    stdout, stderr = run_klp(sample_logfile, "--each-key")
    lines = stdout.splitlines()

    # First event should be split into 3 lines (time, level, message)
    first_event = lines[:3]
    assert any("time=" in line for line in first_event)
    assert any("level=" in line for line in first_event)
    assert any("message=" in line for line in first_event)


def test_context_prefix(sample_logfile):
    """Test context prefixes for grep matches."""
    stdout, stderr = run_klp(
        sample_logfile, "--grep=error", "--before-context=1", "--after-context=1"
    )
    lines = stdout.splitlines()

    # Should show before, match, and after lines with prefixes
    assert any(line.startswith("/ ") for line in lines)  # Before
    assert any(line.startswith("* ") for line in lines)  # Match
    assert any(line.startswith("\\ ") for line in lines)  # After


def test_stats_output(sample_logfile):
    """Test stats output format."""
    stdout, stderr = run_klp(sample_logfile, "--stats")

    # Stats should go to stderr
    assert "Events shown:" in stderr
    assert "Time span shown:" in stderr
    assert "Keys seen:" in stderr
    assert "Log levels seen:" in stderr

    # Should list all our log levels
    assert all(level in stderr for level in ["info", "debug", "warn", "error"])
