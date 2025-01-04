#!/usr/bin/env python3
"""
Incident Log Generator

This script generates realistic application logs that simulate a production incident,
specifically focusing on API server performance degradation. It can operate in two modes:
1. One-time generation of a full incident timeline
2. Continuous generation of real-time logs

The generated logs follow the logfmt format and include various event types such as:
- API requests with response times and status codes
- Background task execution
- System metrics (CPU, memory)
- Database performance issues
- Service health status

Usage:
    # Generate a one-time simulation of an incident timeline
    python generate_incident.py incident.logfmt

    # Generate initial incident logs and continue appending in real-time
    python generate_incident.py --continue incident.logfmt

The script generates realistic application logs that simulate a production incident
where an API server experiences gradual performance degradation. The incident timeline
spans from 6:45 AM to 10:50 AM, with degradation starting at 10:15 AM and leading
to critical failures by 10:45 AM.

Generated logs include:
- API request logs with response times and status codes
- Background task execution (cleanup jobs, metrics collection)
- System metrics (CPU, memory utilization)
- Database performance warnings
- Service health status updates

Output is in logfmt format, suitable for ingestion by log analysis tools.
"""

import random
from datetime import datetime, timedelta, UTC
import json
import argparse
import time
import sys
import os
from typing import List, Dict, Tuple, Optional


class LogGenerator:
    """Manages the generation of realistic application logs."""

    def __init__(self):
        """Initialize log generator with default configuration."""
        self.INCIDENT_START_TIME = datetime(2024, 2, 5, 6, 45, 0)
        self.INCIDENT_END_TIME = datetime(2024, 2, 5, 10, 50, 0)
        self.DEGRADATION_START_TIME = datetime(2024, 2, 5, 10, 15, 0)
        self.CRITICAL_FAILURE_TIME = datetime(2024, 2, 5, 10, 45, 0)

    def generate_realistic_logs(self) -> List[str]:
        """
        Generate a complete sequence of logs representing an incident timeline.

        Returns:
            List[str]: Chronologically ordered log entries in logfmt format
        """
        current_time = self.INCIDENT_START_TIME
        logs = []

        # Generate startup sequence logs
        logs.extend(self._generate_startup_sequence(current_time))
        current_time += timedelta(seconds=5)

        # Set up background task schedule
        background_tasks = self._initialize_background_tasks(current_time)

        # Generate main incident timeline
        while current_time < self.INCIDENT_END_TIME:
            logs.extend(self._generate_time_slice_logs(current_time, background_tasks))
            current_time += timedelta(milliseconds=random.randint(100, 2000))

        return sorted(logs)

    def _generate_startup_sequence(self, start_time: datetime) -> List[str]:
        """
        Generate startup sequence logs for the application.

        Args:
            start_time (datetime): Starting timestamp for the sequence

        Returns:
            List[str]: Startup sequence log entries
        """
        current_time = start_time
        startup_logs = []

        startup_events = [
            ("info", "API server started", {"version": "2.1.4", "host": "web-03.prod"}),
            (
                "info",
                "Connected to primary database",
                {"host": "db-primary.prod", "latency": "3ms"},
            ),
            (
                "info",
                "Connected to cache server",
                {"host": "redis-01.prod", "latency": "2ms"},
            ),
            ("info", "Started background job processor", {"workers": 4}),
            ("info", "Metrics collection initialized", {"interval": "60s"}),
            ("info", "Starting scheduled tasks", {"count": 3}),
        ]

        for level, msg, extras in startup_events:
            startup_logs.append(self._format_log(current_time, level, msg, **extras))
            current_time += timedelta(milliseconds=random.randint(200, 800))

        return startup_logs

    def _initialize_background_tasks(self, start_time: datetime) -> Dict[str, datetime]:
        """
        Initialize background task schedule.

        Args:
            start_time (datetime): Initial timestamp for task scheduling

        Returns:
            Dict[str, datetime]: Mapping of task names to their next execution time
        """
        background_task_schedule = [
            (timedelta(minutes=5), "Cleanup job completed", {"records_processed": 150}),
            (timedelta(minutes=15), "Metrics snapshot taken", {"metrics_count": 42}),
            (
                timedelta(minutes=30),
                "Cache cleanup performed",
                {"entries_removed": 256},
            ),
            (timedelta(hours=1), "Hourly statistics generated", {"reports": 12}),
        ]
        return {
            task: start_time + interval
            for interval, task, _ in background_task_schedule
        }

    def _generate_time_slice_logs(
        self, current_time: datetime, background_tasks: Dict[str, datetime]
    ) -> List[str]:
        """
        Generate logs for a specific time slice, including API requests and system events.

        Args:
            current_time (datetime): Current timestamp
            background_tasks (Dict[str, datetime]): Background task schedule

        Returns:
            List[str]: Log entries for the time slice
        """
        logs = []

        # Generate API request logs
        if random.random() < 0.98:
            logs.extend(self._generate_api_requests(current_time))

        # Generate system health logs during degradation period
        if current_time >= self.DEGRADATION_START_TIME:
            logs.extend(self._generate_degradation_logs(current_time))

        # Generate critical failure logs
        if current_time >= self.CRITICAL_FAILURE_TIME:
            logs.extend(self._generate_critical_failure_logs(current_time))

        return logs

    def _generate_api_requests(self, timestamp: datetime) -> List[str]:
        """
        Generate realistic API request logs with microsecond-precision timestamps.

        Args:
            timestamp (datetime): Base timestamp for this batch of requests

        Returns:
            List[str]: API request log entries with distributed timestamps
        """
        logs = []
        num_requests = random.randint(3, 8)

        # Distribute requests across a small time window (up to 20ms)
        # This ensures no two requests have the exact same timestamp
        time_slots = sorted([random.random() * 20 for _ in range(num_requests)])

        for time_offset in time_slots:
            # Add microsecond-level variance to timestamp
            request_time = timestamp + timedelta(milliseconds=time_offset)

            endpoint = self._generate_endpoint()
            response_time = self._calculate_response_time(request_time, endpoint)
            status = self._generate_status_code(endpoint)

            logs.append(
                self._format_log(
                    request_time,
                    "info",
                    f'{"GET" if endpoint != "/api/orders" else "POST"} {endpoint}',
                    client=self._generate_ip(),
                    user=self._generate_user(),
                    response_time=f"{response_time}ms",
                    status=status,
                )
            )
        return logs

    @staticmethod
    def _generate_ip() -> str:
        """Generate a realistic internal IP address."""
        return f"192.168.{random.randint(1,5)}.{random.randint(1,254)}"

    @staticmethod
    def _generate_user() -> str:
        """Generate a user from weighted distribution of test users."""
        users = [
            "alice",
            "bob",
            "charlie",
            "dave",
            "eve",
            "frank",
            "grace",
            "henry",
            "ivy",
            "jack",
        ]
        weights = [0.3, 0.25, 0.2, 0.1, 0.05, 0.025, 0.025, 0.025, 0.015, 0.01]
        return random.choices(users, weights=weights)[0]

    def _calculate_response_time(self, timestamp: datetime, endpoint: str) -> int:
        """
        Calculate response time for an API request, factoring in degradation period.

        Args:
            timestamp (datetime): Time of the request
            endpoint (str): API endpoint being called

        Returns:
            int: Response time in milliseconds
        """
        # Base response time starts at 80ms
        base_response_time = 80

        # Add degradation if after the degradation start time
        if timestamp >= self.DEGRADATION_START_TIME:
            minutes_since_degradation = (
                timestamp - self.DEGRADATION_START_TIME
            ).total_seconds() / 60
            base_response_time += minutes_since_degradation * 15

        # Add endpoint-specific adjustments
        if endpoint == "/api/orders":
            base_response_time *= 2  # Order endpoints are slower

        # Add some random variance (±10%)
        variance_factor = random.gauss(1.0, 0.1)
        return int(base_response_time * variance_factor)

    def _generate_status_code(self, endpoint: str) -> int:
        """
        Generate appropriate HTTP status code based on endpoint and error rates.

        Args:
            endpoint (str): API endpoint being called

        Returns:
            int: HTTP status code
        """
        if random.random() < 0.98:  # 98% success rate for most endpoints
            return 200

        if endpoint == "/api/orders":
            # Orders have a higher error rate, with 400 being more common
            return random.choice([400, 400, 400, 401, 429])
        else:
            # Other endpoints have a mix of possible errors
            return random.choice([400, 401, 404, 429])

    @staticmethod
    def _generate_endpoint() -> str:
        """Generate an API endpoint based on weighted distribution."""
        endpoints = [
            ("/api/products", 0.3),
            ("/api/cart", 0.25),
            ("/api/orders", 0.15),
            ("/api/users/profile", 0.1),
            ("/api/categories", 0.1),
            ("/api/search", 0.05),
            ("/api/recommendations", 0.03),
            ("/api/wishlist", 0.02),
        ]
        endpoint, _ = random.choices(endpoints, weights=[w for _, w in endpoints])[0]
        return endpoint

    def _generate_degradation_logs(self, current_time: datetime) -> List[str]:
        """
        Generate system health and performance warning logs during degradation period.

        Args:
            current_time (datetime): Current timestamp

        Returns:
            List[str]: Warning logs about system health
        """
        logs = []
        minutes_since_degradation = (
            current_time - self.DEGRADATION_START_TIME
        ).total_seconds() / 60

        # Chance of warnings increases over time
        base_warning_chance = 0.02 + (minutes_since_degradation * 0.001)

        # Possible slow database query
        if random.random() < base_warning_chance:
            query_time = int(800 + minutes_since_degradation * 20)
            logs.append(
                self._format_log(
                    current_time,
                    "warning",
                    "Slow database query detected",
                    query="SELECT * FROM products WHERE category IN (SELECT id FROM categories WHERE parent_id = ?)",
                    duration=f"{query_time}ms",
                )
            )

        # Possible memory pressure
        if random.random() < base_warning_chance:
            memory_used = int(5000 + minutes_since_degradation * 30)
            logs.append(
                self._format_log(
                    current_time,
                    "warning",
                    "High memory usage detected",
                    memory_used_mb=memory_used,
                    memory_total_mb=8192,
                    host="web-03.prod",
                )
            )

        # Possible CPU pressure
        if random.random() < base_warning_chance:
            cpu_percent = 70 + (minutes_since_degradation * 0.5)
            logs.append(
                self._format_log(
                    current_time,
                    "warning",
                    "High CPU usage",
                    cpu_percent=round(cpu_percent, 1),
                    host="web-03.prod",
                )
            )

        return logs

    def generate_continuous_logs(self, current_time: datetime) -> Optional[str]:
        """
        Generate a single log entry for continuous real-time operation.

        Args:
            current_time (datetime): Current timestamp

        Returns:
            Optional[str]: A log entry if one should be generated, None otherwise
        """
        if random.random() < 0.98:  # 98% chance of API request
            endpoint = self._generate_endpoint()
            response_time = int(random.gauss(80, 8))
            status = (
                200 if random.random() < 0.98 else random.choice([400, 401, 404, 429])
            )

            return self._format_log(
                current_time,
                "info",
                f'{"GET" if endpoint != "/api/orders" else "POST"} {endpoint}',
                client=self._generate_ip(),
                user=self._generate_user(),
                response_time=f"{response_time}ms",
                status=status,
            )

        if random.random() < 0.02:  # 2% chance of warning/error
            warning_types = [
                (
                    "warning",
                    "Slow database query detected",
                    {
                        "query": "SELECT * FROM products",
                        "duration": f"{random.randint(800,1200)}ms",
                    },
                ),
                (
                    "warning",
                    "High memory usage detected",
                    {
                        "memory_used_mb": random.randint(5000, 7000),
                        "memory_total_mb": 8192,
                        "host": "web-03.prod",
                    },
                ),
                (
                    "error",
                    "Database query timeout",
                    {"error_code": "DB_TIMEOUT", "duration": "3000ms"},
                ),
            ]
            level, msg, extras = random.choice(warning_types)
            return self._format_log(current_time, level, msg, **extras)

        return None

    @staticmethod
    def _format_log(timestamp: datetime, level: str, message: str, **kwargs) -> str:
        """
        Format a log entry in logfmt format.

        Args:
            timestamp (datetime): Log timestamp
            level (str): Log level (info, warning, error, critical)
            message (str): Log message
            **kwargs: Additional key-value pairs to include in the log

        Returns:
            str: Formatted log entry
        """
        extras = " ".join(f"{k}={json.dumps(v)}" for k, v in kwargs.items())
        return f"time={timestamp.isoformat()}Z level={level} message={json.dumps(message)} {extras}"

    def _generate_critical_failure_logs(self, current_time: datetime) -> List[str]:
        """
        Generate error and critical failure logs during the severe degradation period.

        Args:
            current_time (datetime): Current timestamp

        Returns:
            List[str]: Error and critical failure logs
        """
        logs = []

        # 30% chance of errors during critical period
        if random.random() < 0.3:
            error_types = [
                (
                    "Database query timeout",
                    {
                        "query": "SELECT p.*, c.name FROM products p JOIN categories c ON p.category_id = c.id",
                        "error_code": "DB_TIMEOUT",
                        "duration": "3000ms",
                    },
                ),
                (
                    "Database connection error",
                    {"error": "Too many connections", "host": "db-primary.prod"},
                ),
                (
                    "Failed to process request",
                    {
                        "path": self._generate_endpoint(),
                        "client": self._generate_ip(),
                        "error": "Database unavailable",
                        "status": 503,
                    },
                ),
            ]
            error_msg, error_extras = random.choice(error_types)
            logs.append(
                self._format_log(current_time, "error", error_msg, **error_extras)
            )

            # 10% chance of critical health check failure after errors
            if random.random() < 0.1:
                logs.append(
                    self._format_log(
                        current_time,
                        "critical",
                        "Service health check failed",
                        healthy=False,
                        error_count=random.randint(3, 8),
                        last_success=(
                            current_time - timedelta(seconds=random.randint(10, 30))
                        ).isoformat()
                        + "Z",
                    )
                )

        return logs


def main():
    """
    Main entry point for the log generator script.
    Handles command line arguments and manages log generation modes.
    """
    parser = argparse.ArgumentParser(
        description="Generate realistic application logs simulating a production incident",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate a complete incident timeline
    %(prog)s incident.logfmt
    
    # Generate initial incident and continue adding real-time logs
    %(prog)s --continue incident.logfmt

The script simulates an API server incident with increasing degradation:
- Timeline: 6:45 AM - 10:50 AM
- Performance degradation begins: 10:15 AM
- Critical failures start: 10:45 AM""",
    )

    parser.add_argument(
        "logfile", help="Path to the output log file (in logfmt format)"
    )
    parser.add_argument(
        "--continue",
        dest="continuous",
        action="store_true",
        help="After generating initial incident logs, continue appending new events in real-time",
    )
    args = parser.parse_args()

    log_file = args.logfile
    generator = LogGenerator()

    if not os.path.exists(log_file):
        print(f"Generating initial incident logs to {log_file}")
        logs = generator.generate_realistic_logs()
        with open(log_file, "w") as f:
            for log in logs:
                f.write(log + "\n")

    if args.continuous:
        print("Starting continuous log generation...")
        with open(log_file, "a") as f:
            while True:
                current_time = datetime.now(UTC)
                log_entry = generator.generate_continuous_logs(current_time)
                if log_entry:
                    f.write(log_entry + "\n")
                    f.flush()
                time.sleep(random.uniform(0.1, 2.0))


if __name__ == "__main__":
    main()
