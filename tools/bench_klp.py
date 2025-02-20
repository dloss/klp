#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import random
import subprocess
import sys
import time
from statistics import mean, stdev
from typing import List, Dict, Tuple


def generate_logfmt_line() -> str:
    ts = dt.datetime.now(dt.timezone.utc).isoformat()
    levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    messages = [
        "User login successful",
        "Database connection established",
        "Processing request",
        "Cache miss",
        "Metrics collection started",
        "Background job completed",
        "Request validation failed",
        "Rate limit exceeded",
    ]
    return f'ts="{ts}" level="{random.choice(levels)}" msg="{random.choice(messages)}"'


def generate_test_file(filename: str, num_lines: int) -> None:
    with open(filename, "w") as f:
        for _ in range(num_lines):
            f.write(generate_logfmt_line() + "\n")


def generate_jsonl_line() -> str:
    data = {
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "level": random.choice(["DEBUG", "INFO", "WARNING", "ERROR"]),
        "message": random.choice(
            [
                "User login successful",
                "Database connection established",
                "Processing request",
                "Cache miss",
                "Metrics collection started",
                "Background job completed",
                "Request validation failed",
                "Rate limit exceeded",
            ]
        ),
    }
    return json.dumps(data)


def generate_jsonl_file(filename: str, num_lines: int) -> None:
    with open(filename, "w") as f:
        for _ in range(num_lines):
            f.write(generate_jsonl_line() + "\n")


def verify_setup() -> None:
    """Verify klp is available and test files can be created."""
    try:
        subprocess.run(["klp", "--version"], capture_output=True, check=True)
    except FileNotFoundError:
        print("Error: klp not found in PATH. Please install klp first.")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"Error running klp: {e}")
        sys.exit(1)


def run_benchmark(cmd: str, runs: int = 5) -> Tuple[float, float]:
    """Run a command multiple times and return mean and stdev of execution times."""
    times = []
    for _ in range(runs):
        start = time.perf_counter()
        result = subprocess.run(cmd, shell=True, capture_output=True)
        end = time.perf_counter()
        if result.returncode != 0:
            print(f"Error running command: {cmd}")
            print(f"stderr: {result.stderr.decode()}")
            print(f"stdout: {result.stdout.decode()}")
            return 0.0, 0.0
        times.append(end - start)
    return mean(times), stdev(times)


def format_time(seconds: float) -> str:
    """Format time in seconds to human readable string."""
    if seconds < 0.001:
        return f"{seconds * 1000000:.2f} µs"
    elif seconds < 1:
        return f"{seconds * 1000:.2f} ms"
    else:
        return f"{seconds:.2f} s"


def main() -> None:
    # Get script directory for relative paths
    script_dir = os.path.dirname(os.path.abspath(__file__))

    parser = argparse.ArgumentParser(description="Run klp performance tests")
    parser.add_argument(
        "--lines", type=int, default=100000, help="Number of lines in test files"
    )
    parser.add_argument("--runs", type=int, default=5, help="Number of runs per test")
    parser.add_argument(
        "--debug", action="store_true", help="Show additional debug information"
    )
    args = parser.parse_args()

    verify_setup()

    # Base command prefix with common options
    base_cmd = "klp --no-color --errors print"

    test_data_dir = os.path.join(script_dir, "test_data")
    os.makedirs(test_data_dir, exist_ok=True)

    logfmt_path = os.path.join(test_data_dir, "test.logfmt")
    jsonl_path = os.path.join(test_data_dir, "test.jsonl")

    print(f"Generating test files with {args.lines} lines each...")
    generate_test_file(logfmt_path, args.lines)
    generate_jsonl_file(jsonl_path, args.lines)

    if args.debug:
        print(f"\nVerifying generated files:")
        print(f"logfmt file size: {os.path.getsize(logfmt_path)} bytes")
        print(f"jsonl file size: {os.path.getsize(jsonl_path)} bytes")
        print("\nFirst few lines of logfmt file:")
        with open(logfmt_path) as f:
            print("".join(f.readlines()[:3]))

    # Define test cases
    test_cases = [
        {
            "name": "Basic logfmt parsing",
            "cmd": f"{base_cmd} {logfmt_path} > /dev/null",
        },
        {
            "name": "JSONL parsing",
            "cmd": f"{base_cmd} -f jsonl {jsonl_path} > /dev/null",
        },
        {
            "name": "Filtered by log level",
            "cmd": f"{base_cmd} -l error,warning {logfmt_path} > /dev/null",
        },
        {
            "name": "Time-based filtering",
            "cmd": f"{base_cmd} --since 1h {logfmt_path} > /dev/null",
        },
        {
            "name": "Grep filtering",
            "cmd": f"{base_cmd} -g 'error' {logfmt_path} > /dev/null",
        },
        {
            "name": "Multiple grep patterns",
            "cmd": f"{base_cmd} -g 'error' -g 'warning' {logfmt_path} > /dev/null",
        },
        {
            "name": "With key selection",
            "cmd": f"{base_cmd} -k timestamp,level,message {logfmt_path} > /dev/null",
        },
        {
            "name": "Output as JSONL",
            "cmd": f"{base_cmd} -F jsonl {logfmt_path} > /dev/null",
        },
        {
            "name": "Output as CSV",
            "cmd": f"{base_cmd} -F csv -k timestamp,level,message {logfmt_path} > /dev/null",
        },
        {
            "name": "Parallel processing",
            "cmd": f"{base_cmd} --parallel 0 {logfmt_path} > /dev/null",
        },
    ]

    # Run benchmarks
    print(f"\nRunning benchmarks ({args.runs} runs per test)...\n")
    results = []
    for case in test_cases:
        print(f"Testing: {case['name']}")
        mean_time, std_dev = run_benchmark(case["cmd"], args.runs)
        if mean_time > 0:  # Only add successful tests
            results.append({"name": case["name"], "mean": mean_time, "stdev": std_dev})
        print(f"  Mean: {format_time(mean_time)} ± {format_time(std_dev)}\n")

    # Print summary
    if results:
        print("\nSummary (sorted by mean time):")
        print("-" * 80)
        for result in sorted(results, key=lambda x: x["mean"]):
            print(
                f"{result['name']:<30} {format_time(result['mean'])} ± {format_time(result['stdev'])}"
            )


if __name__ == "__main__":
    main()
