#!/usr/bin/env python3
import random
import datetime
import time

log_levels = ["debug", "info", "warn", "error", "fatal"]
services = ["web", "auth", "db", "cache", "api"]
actions = ["get", "post", "put", "delete", "patch"]
status_codes = [200, 201, 204, 400, 401, 403, 404, 500]
user_ids = list(range(1000, 1020))


def generate_logfmt_entry():
    timestamp = datetime.datetime.now().isoformat()
    level = random.choice(log_levels)
    service = random.choice(services)
    action = random.choice(actions)
    status = random.choice(status_codes)
    user = random.choice(user_ids)
    latency = round(random.uniform(0.1, 2.0), 3)

    message = f"{action.upper()} request processed"

    logfmt = (
        f'time="{timestamp}" level={level} service={service} '
        f"action={action} status={status} user_id={user} "
        f'latency={latency} message="{message}"'
    )

    return logfmt


def generate_logfmt_stream(duration_seconds=60, entries_per_second=1):
    end_time = time.time() + duration_seconds
    while time.time() < end_time:
        for _ in range(entries_per_second):
            print(generate_logfmt_entry(), flush=True)
        time.sleep(1)


if __name__ == "__main__":
    try:
        generate_logfmt_stream()
    except KeyboardInterrupt:
        pass
