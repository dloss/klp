"""Input-path error handling: a directory (or otherwise unreadable regular
input path) must fail with a clean one-line error on stderr and exit code 1,
not an unhandled traceback."""

import os
import subprocess
import sys

KLP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "klp.py"))


def run_klp_raw(*args):
    cmd = [sys.executable, KLP_PATH, "--no-color", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_directory_as_input_fails_cleanly(tmp_path):
    """Passing a directory as the log file must exit 1 without a traceback."""
    result = run_klp_raw(str(tmp_path))
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert result.stderr.strip() != ""


def test_missing_file_still_fails_cleanly(tmp_path):
    """The pre-existing missing-file path keeps working after the fix."""
    missing = str(tmp_path / "does-not-exist-12345.log")
    result = run_klp_raw(missing)
    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "No such file or directory" in result.stderr
