#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 Dirk Loss
"""
klp: Kool Logfmt Parser

For logs in key=value format (and some others), show only the interesting parts
"""

import argparse
import contextlib
import csv
import dataclasses
import datetime as dt
import errno
import gzip
import inspect
import io
import json
import os
import pprint
import re
import shlex
import shutil
import sqlite3
import sys
import textwrap
import unittest
import zipfile

# Some modules to make available for filtering and templating
import base64
import collections
import datetime
import hashlib
import itertools
import math
import random
import string

__version__ = "0.70.2"

INPUT_QUOTE = r"\""

# Names of keys our program cares about. Use lowercase keys here.
TS_KEYS = "_klp_timedelta ts time timestamp t at _ts _klp_ts".split()
MSG_KEYS = "msg message".split()
LEVEL_KEYS = "log_level level lvl loglevel severity".split()

# Regular expressions
RE_LOGFMT = re.compile(r'([\w.]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s]*))')
RE_WHITESPACE = re.compile(r"\s")
RE_EOL_OR_TAB = re.compile(r"\\n|\\t|\\r")
RE_EXTRACT_KEY = re.compile(r"^(\w+)~(.*)")
RE_CLF = re.compile(
    r'(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+)'
)
RE_COMBINED = re.compile(
    r'(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

RE_UNIX = re.compile(
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s+"
    r"(?P<message>.*)"
)


# ANSI Escape Codes and a short, temporary replacement sentinel that should not occur otherwise in the text
COLOR_CODES = {
    "black": ("\x1b[30m", "\x01"),
    "red": ("\x1b[31m", "\x02"),
    "green": ("\x1b[32m", "\x03"),
    "yellow": ("\x1b[33m", "\x04"),
    "blue": ("\x1b[34m", "\x05"),
    "magenta": ("\x1b[35m", "\x06"),
    "cyan": ("\x1b[36m", "\x07"),
    "white": ("\x1b[37m", "\x08"),
    # Skip 0x09 to 0x0D (not supported by textwrap.wrap)
    "bright_black": ("\x1b[1;30m", "\x0e"),
    "bright_red": ("\x1b[1;31m", "\x0f"),
    "bright_green": ("\x1b[1;32m", "\x10"),
    "bright_yellow": ("\x1b[1;33m", "\x11"),
    "bright_blue": ("\x1b[1;34m", "\x12"),
    "bright_magenta": ("\x1b[1;35m", "\x13"),
    "bright_cyan": ("\x1b[1;36m", "\x14"),
    "bright_white": ("\x1b[1;37m", "\x15"),
    "bold": ("\x1b[1m", "\x16"),
    "off": ("\x1b[0m", "\x17"),
    "underline": ("\x1b[4m", "\x18"),
    "italic": ("\x1b[3m", "\x19"),
    "reverse": ("\x1b[7m", "\x1a"),
}
COLOR = {key: color for key, (color, _) in COLOR_CODES.items()}
SCOLOR = {key: scolor for key, (_, scolor) in COLOR_CODES.items()}
THEMES = {
    "default": {
        "keys": "green",
        "quotes": "off",
        "message_key": "off",
        "timestamp_key": "off",
        "levels": {
            "trace": "cyan",
            "debug": "bright_cyan",
            "info": "bright_green",
            "notice": "bright_green",
            "warn": "bright_yellow",
            "warning": "bright_yellow",
            "error": "bright_red",
            "err": "bright_red",
            "fatal": "bright_red",
            "panic": "bright_red",
            "alert": "bright_red",
            "crit": "bright_red",
            "emerg": "bright_red",
        },
        "context_prefix": {
            "before": "blue",
            "match": "bright_magenta",
            "after": "blue",
            "fuse_first": "blue",
            "fuse_last": "blue",
        },
        "skipped_marker": {"before": "cyan", "number": "cyan", "after": "cyan"},
        "gap_marker": {"before": "blue", "label": "blue", "after": "blue"},
    },
    "classic": {
        "keys": "green",
        "quotes": "black",
        "message_key": "bright_black",
        "timestamp_key": "off",
        "levels": {
            "trace": "blue",
            "debug": "cyan",
            "info": "bright_green",
            "notice": "bright_green",
            "warn": "bright_yellow",
            "warning": "bright_yellow",
            "error": "bright_red",
            "err": "bright_red",
            "fatal": "bright_red",
            "panic": "bright_red",
            "alert": "bright_red",
            "crit": "bright_red",
            "emerg": "bright_red",
        },
        "context_prefix": {
            "before": "blue",
            "match": "bright_magenta",
            "after": "blue",
            "fuse_first": "blue",
            "fuse_last": "blue",
        },
        "skipped_marker": {"before": "blue", "number": "black", "after": "blue"},
        "gap_marker": {"before": "blue", "label": "black", "after": "blue"},
    },
    "light": {
        "keys": "blue",
        "quotes": "off",
        "message_key": "off",
        "timestamp_key": "off",
        "levels": {
            "trace": "magenta",
            "debug": "cyan",
            "info": "green",
            "notice": "green",
            "warn": "yellow",
            "warning": "yellow",
            "error": "red",
            "err": "red",
            "fatal": "bright_red",
            "panic": "bright_red",
            "alert": "bright_red",
            "crit": "bright_red",
            "emerg": "bright_red",
        },
        "context_prefix": {
            "before": "blue",
            "match": "magenta",
            "after": "blue",
            "fuse_first": "blue",
            "fuse_last": "blue",
        },
        "skipped_marker": {"before": "cyan", "number": "bright_black", "after": "cyan"},
        "gap_marker": {"before": "blue", "label": "bright_black", "after": "blue"},
    },
    "tty": {
        "keys": "italic",
        "quotes": "off",
        "message_key": "off",
        "timestamp_key": "off",
        "levels": {
            "trace": "off",
            "debug": "off",
            "info": "off",
            "notice": "off",
            "warn": "bold",
            "warning": "bold",
            "error": "reverse",
            "err": "reverse",
            "fatal": "reverse",
            "panic": "reverse",
            "alert": "reverse",
            "crit": "reverse",
            "emerg": "reverse",
        },
        "context_prefix": {
            "before": "off",
            "match": "reverse",
            "after": "off",
            "fuse_first": "italic",
            "fuse_last": "italic",
        },
        "skipped_marker": {"before": "off", "number": "underline", "after": "off"},
        "gap_marker": {"before": "off", "label": "underline", "after": "off"},
    },
}

BUILTIN_REGEXES = {
    # https://www.regular-expressions.info/email.html
    "email": [r"\b(([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b))"],
    "err": [
        r"(?i)\b((error|err|panic|crit|critical|alert|fatal|emerg|failed|failure|exception))\b"
    ],
    "fqdn": [
        r"\b(((?:[a-z](?:[a-z0-9-]{0,63}[a-z0-9])?\.){2,}[a-z0-9][a-z0-9-]{0,8}))"
    ],
    "function": [r"\b((\w+\([^)]*\)))"],
    "gitcommit": [r"\b(([0-9a-fA-F]{7,40}))\b"],
    "hexcolor": [r"((#[0-9A-Fa-f]{6}))\b"],
    "ipv4": [
        r"\b((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b"
    ],
    "ipv6": [
        r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"
    ],
    "json": [r"((\{[^{}]*?\}))"],
    "isotime": [
        r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b)"
    ],
    "jwt": [r"((eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*))"],
    "mac": [
        r"\b(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))\b",
        r"\b(([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4}))\b",
    ],
    "md5": [r"\b(([a-fA-F0-9]{32}))\b"],
    "oauth": [r"\b((ya29\.[0-9A-Za-z_-]+))\b"],
    "path": [r"((^|(?<=[^./\w-]))(/[.\w-]+)+/?)"],
    "sha1": [r"\b(([a-fA-F0-9]{40}))\b"],
    "sha256": [r"\b(([a-fA-F0-9]{64}))\b"],
    "sql": [
        r"\b((?i:(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|MERGE))\b)"
    ],
    "url": [
        r"\b(((?:[a-z][a-z0-9+.-]*):\/\/(?:(?:[^\s:@]+(?::[^\s:@]*)?@)?(?:[^\s:/?#]+)(?::\d+)?(?:\/[^\s?#]*)?(?:\?[^\s#]*)?(?:#[^\s]*)?)))\b"
    ],
    "uuid": [
        r"\b(([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))\b"
    ],
    "version": [r"\b(([vV])\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+)?)\b"],
    "winregistry": [r"((HKEY_[A-Z_]+(?:\\[A-Za-z0-9_]+)+))"],
}


EPILOG = f"""
INTERVAL units: us=microseconds/ms=milliseconds/s=seconds/m=minutes/h=hours/d=days/w=weeks"
Highlighted keys: {','.join(TS_KEYS + MSG_KEYS + LEVEL_KEYS)}
"""

terminal_width = shutil.get_terminal_size((80, 24)).columns


def build_globals_dict(modules):
    d = {}
    for module in modules:
        name = module.__name__
        alt_name = "_" + name
        d[name] = d[alt_name] = module
    return d


def print_output(*myargs, **kwargs):
    try:
        print(*myargs, **kwargs, file=args.output_file)
    except UnicodeEncodeError as e:
        print(
            f"Warning: Unable to encode some characters using {args.output_encoding} encoding. Skipping problematic output.",
            file=sys.stderr,
        )


def extract_json(text):
    """
    Extract the first JSON object or array from a given text.

    Parameters:
    text (str): The string containing the text from which to extract the JSON object or array.

    Returns:
    str: The first valid JSON object or array found in the given text.

    Raises:
    ValueError: If no valid JSON object or array can be found in the input text.

    Example:
    >>> extract_json('foo { "key": "value" } bar')
    '{ "key": "value" }'

    >>> extract_json('foo [1, 2, 3] bar')
    '[1, 2, 3]'
    """
    json_start_chars = {"{", "["}
    json_end_chars = {"}": "{", "]": "["}
    start = None
    stack = []

    for i, char in enumerate(text):
        if char in json_start_chars:
            if start is None:
                start = i
            stack.append(char)
        elif char in json_end_chars:
            if stack and stack[-1] == json_end_chars[char]:
                stack.pop()
                if not stack:
                    json_str = text[start : i + 1]
                    try:
                        json.loads(json_str)
                        return json_str
                    except json.JSONDecodeError:
                        pass
                    start = None

    raise ValueError(f"Could not extract JSON from {text!r}")


def pprint_json(json_string, indent=2, sort_keys=True, ensure_ascii=False):
    """
    Pretty-print a JSON string.

    Args:
        json_string (str): The JSON string to be pretty-printed.
        indent (int, optional): Number of spaces to use for indentation. Defaults to 2.
        sort_keys (bool, optional): Whether to sort the dictionary keys. Defaults to True.
        ensure_ascii (bool, optional): Whether to escape non-ASCII characters. Defaults to False.

    Returns:
        str: A pretty-printed JSON string.

    Raises:
        ValueError: If the provided string is not a valid JSON.

    Example:
        >>> input_json = '{"name":"John", "age":30, "city":"New York"}'
        >>> pprint_json(input_json, indent=4)
        '{
            "age": 30,
            "city": "New York",
            "name": "John"
        }'
    """
    try:
        parsed_json = json.loads(json_string)
        pretty_json = json.dumps(
            parsed_json, indent=indent, sort_keys=sort_keys, ensure_ascii=ensure_ascii
        )
        return pretty_json
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON string: {e}")


def guess_datetime(timestamp):
    """
    Attempt to convert a given timestamp string into a datetime object using various datetime converters.

    Args:
        timestamp (str): The timestamp string to be converted.

    Returns:
        datetime or None: A datetime object if conversion is successful, otherwise None.

    Raises:
        AttributeError, ValueError, TypeError: These exceptions are caught during conversion attempts and ignored.

    Side Effects:
        The global `dt_conv_order` list is updated to prioritize successful converters for future use.
    """
    global dt_conv_order
    datetime = None
    for i in dt_conv_order:
        converter = datetime_converters[i]
        try:
            datetime = converter(timestamp)
            # print("guess", i, timestamp, "as", datetime, datetime.tzname(), file=sys.stderr) # debug
            break
        except (AttributeError, ValueError, TypeError):
            continue
    # Bring found converter to the front so that it's tried first next time
    if not dt_conv_order[0] == i:
        dt_conv_order.insert(0, dt_conv_order.pop(i))
    return datetime


def format_datetime(val):
    """
    Formats a given datetime string into a standardized ISO 8601 format string with milliseconds precision.

    The function converts the input datetime string to either local time or UTC time based on the specified
    command-line arguments (`--localtime` or `--utc`). It then formats the datetime object into the ISO 8601
    format, including milliseconds.

    Args:
        val (str): The datetime string to be formatted.

    Returns:
        str: The formatted datetime string in ISO 8601 format with milliseconds precision. The returned string
             will be in local time if `--localtime` is True, or in UTC time with a "Z" suffix if `--utc`
             is True.

    Raises:
        ValueError: If the input `val` cannot be parsed as a datetime.

    Notes:
        - The function uses the `to_datetime` function to parse the input datetime string.
        - The `args` object is expected to have the boolean attributes `localtime` and `utc` which determine
          the desired timezone for the output.

    Example:
        >>> args.localtime = True
        >>> format_datetime("2023-10-05 14:48:00")
        '2023-10-05T14:48:00.000Z'

        >>> args.utc = True
        >>> format_datetime("2023-10-05 14:48:00")
        '2023-10-05T14:48:00.000Z'
    """
    try:
        if args.localtime:
            val = to_datetime(val).astimezone().isoformat(timespec="milliseconds")
        elif args.utc:
            val = (
                to_datetime(val)
                .astimezone(dt.timezone.utc)
                .isoformat(timespec="milliseconds")
                .replace("+00:00", "Z")
            )
    except ValueError as e:
        if args.debug:
            print_err(e)
    return val


def extract_regex(pattern, s, *groupargs):
    r"""
    Extracts substring(s) from a given string that matches a specified regular expression pattern.

    Parameters:
    pattern (str): The regular expression pattern to search for.
    s (str): The string to search within.
    *groupargs (int): Variable length argument list specifying group indices to retrieve from the match.

    Returns:
    str or tuple: The matched group(s) if the pattern is found; otherwise, None.

    Examples:
    >>> extract_regex(r"(\d+)", "There are 123 apples", 0)
    '123'

    >>> extract_regex(r"(\d+)\D+(\d+)", "12 apples and 34 oranges", 1, 2)
    ('12', '34')
    """
    match = re.search(pattern, s)
    if match:
        return match.group(*groupargs)
    return None


def extract_builtin_regex(regex_name, s):
    if regex_name in BUILTIN_REGEXES:
        pattern = BUILTIN_REGEXES[regex_name][0]
        match = re.search(pattern, s)
        if match:
            return match.group()
    return None


def create_extraction_function(regex_name):
    def extraction_function(s):
        return extract_builtin_regex(regex_name, s)

    extraction_function.__name__ = f"extract_{regex_name}"
    return extraction_function


def apply_input_exec(event):
    events = [event]
    if args.input_exec:
        for code in args.input_exec:
            new_events = []
            for event in events:
                new_events.extend(input_exec(code, event))
            events = new_events
    return events


def parse_linebased(line, format):
    def identity(x):
        return x

    format_parsers = {
        # line-based
        "logfmt": parse_logfmt,
        "jsonl": parse_jsonl,
        "clf": parse_clf,
        "combined": parse_combined,
        "unix": parse_unix,
        "line": parse_line,
        "ts1m": parse_ts1m,
        "ts1lm": parse_ts1lm,
        "ts2m": parse_ts2m,
        "ts2lm": parse_ts2lm,
        "ts3m": parse_ts3m,
        "ts3lm": parse_ts3lm,
        "ts4m": parse_ts4m,
        "ts4lm": parse_ts4lm,
        "ts5m": parse_ts5m,
        "ts5lm": parse_ts5lm,
        # Non-line-based (have already been parsed)
        "json": identity,
        "csv": identity,
        "tsv": identity,
        "psv": identity,
        "table": identity,
        "data": identity,
    }

    parser = format_parsers.get(format)
    if not parser:
        raise ValueError(f"Unknown input format: {format}")

    return parser(line)


def parse_logfmt(text):
    """
    Parses a logfmt-formatted string into a dictionary.

    logfmt is a log format that produces logs as a single line where key-value pairs are
    separated by spaces, and values can be unquoted or quoted.

    Args:
        text (str): A logfmt-formatted string.

    Returns:
        dict: A dictionary where keys are the logfmt keys and values are the corresponding
        unescaped quoted values or unquoted values.
    """
    return {
        key: (unescape(quoted_val) if quoted_val else unquoted_val)
        for key, quoted_val, unquoted_val in RE_LOGFMT.findall(text)
    }


def parse_kv(text, sep=None, kvsep="="):
    """
    Parses a string into key-value pairs based on given separators.

    Args:
        text (str): The input string to parse.
        sep (str or re.Pattern, optional): The separator that divides different key-value pairs in the input string.
                                           If None, any whitespace string is a separator.
                                           Can also be a compiled regular expression.
        kvsep (str, optional): The separator that divides keys from values within each pair. Default is "=".

    Returns:
        dict: A dictionary where the keys are extracted from the input string based on the separators.
              Only columns containing the key-value separator will be included.

    Raises:
        ValueError: If there are issues with splitting or interpreting the key-value pairs.
    """
    if isinstance(sep, re.Pattern):
        columns = re.split(sep, text)
    else:
        columns = text.split(sep)

    result = {}
    for column in columns:
        if kvsep in column:
            key, val = column.split(kvsep, maxsplit=1)
            result[key] = val
    return result


def parse_jsonl(line):
    """
    Parses a line of JSONL (JSON Lines) and extracts the top-level strings, converting
    non-string values to their string representations.

    The function focuses on handling top-level strings within a JSON object. Any text
    before or after the JSON object in the given line is ignored. If the JSON object
    is invalid, an empty dictionary is returned.

    Args:
        line (str): A string containing a JSON object within a line of text.

    Returns:
        dict: A dictionary where the keys represent the sanitized JSON keys and the
              values are the top-level string or stringified non-string values of the
              JSON object.

    Raises:
        None. If JSON decoding fails, an empty dictionary is returned. If `--debug`
        is enabled, the function will print debug information about the error.

    Example:
        >>> parse_jsonl('some text {"key": "value", "num": 123} and more text')
        {'key': 'value', 'num': '123'}
    """
    # Only handle top-level strings. Everything else is converted into a string
    result = {}
    try:
        # Ignore text before and after JSON object
        json_str = line[line.index("{") : line.rindex("}") + 1]
        json_data = json.loads(json_str)
    except (ValueError, json.decoder.JSONDecodeError) as exc:
        if args.debug:
            print_err(repr(line))
            print_err("Invalid JSON syntax in the above line:", exc)
        return result
    for key, val in flatten_object(json_data).items():
        if isinstance(val, str):
            result[sanitize_key(key)] = val
        else:
            result[sanitize_key(key)] = repr(val)
    return result


def parse_clf(line):
    """
    Parses a line in Common Log Format (CLF) and returns a dictionary of its components.

    Args:
        line (str): A single line string in CLF format.

    Returns:
        dict: A dictionary containing the components of the CLF line. If the 'size' field
              in the log is '-', it is converted to '0'. Returns an empty dictionary if
              the line does not match the expected CLF format.
    """
    match = RE_CLF.match(line)
    if match:
        d = match.groupdict()
        if d["size"] == "-":
            d["size"] = "0"
        return d
    else:
        return {}


def parse_combined(line):
    """
    Parse a log entry in Combined Log Format.

    This function uses a regular expression to match and parse a line of text
    representing a log entry in Combined Log Format. If the match is successful,
    it returns a dictionary containing the parsed data. If the size field in the
    log entry is "-", it replaces it with "0". If the match is unsuccessful, it
    returns an empty dictionary.

    Args:
        line (str): A single log entry in Combined Log Format.

    Returns:
        dict: A dictionary with the parsed log data, or an empty dictionary if
              the log entry doesn't match the Combined Log Format.
    """
    match = RE_COMBINED.match(line)
    if match:
        d = match.groupdict()
        if d["size"] == "-":
            d["size"] = "0"
        return d
    else:
        return {}


def parse_unix(line):
    """
    Parse a line of log data in typical format for Unix servers
    (timestamp, hostname, service, and optional pid)
    and extract structured information.

    Args:
        line (str): A single line of log data in Unix format.

    Returns:
        dict: A dictionary containing the extracted components where the keys are
              'timestamp', 'hostname', 'service', and 'message'. The 'pid' key is included
              only if it is present in the log line; otherwise, it is excluded.
    """
    match = RE_UNIX.match(line)
    if match:
        return {
            k: v for k, v in match.groupdict().items() if k != "pid" or v is not None
        }
    else:
        return {}


def parse_ts1m(line):
    ts1, msg = line.split(maxsplit=1)
    return {"timestamp": f"{ts1}", "message": msg}


def parse_ts1lm(line):
    ts1, level, msg = line.split(maxsplit=2)
    return {"timestamp": f"{ts1}", "level": level, "message": msg}


def parse_ts2m(line):
    ts1, ts2, msg = line.split(maxsplit=2)
    return {"timestamp": f"{ts1} {ts2}", "message": msg}


def parse_ts2lm(line):
    ts1, ts2, level, msg = line.split(maxsplit=3)
    return {"timestamp": f"{ts1} {ts2}", "level": level, "message": msg}


def parse_ts3m(line):
    ts1, ts2, ts3, msg = line.split(maxsplit=3)
    return {"timestamp": f"{ts1} {ts2} {ts3}", "message": msg}


def parse_ts3lm(line):
    ts1, ts2, ts3, level, msg = line.split(maxsplit=4)
    return {"timestamp": f"{ts1} {ts2} {ts3}", "level": level, "message": msg}


def parse_ts4m(line):
    ts1, ts2, ts3, ts4, msg = line.split(maxsplit=4)
    return {"timestamp": f"{ts1} {ts2} {ts3} {ts4}", "message": msg}


def parse_ts4lm(line):
    ts1, ts2, ts3, ts4, level, msg = line.split(maxsplit=5)
    return {"timestamp": f"{ts1} {ts2} {ts3} {ts4}", "level": level, "message": msg}


def parse_ts5m(line):
    ts1, ts2, ts3, ts4, ts5, msg = line.split(maxsplit=5)
    return {"timestamp": f"{ts1} {ts2} {ts3} {ts4} {ts5}", "message": msg}


def parse_ts5lm(line):
    ts1, ts2, ts3, ts4, ts5, level, msg = line.split(maxsplit=6)
    return {
        "timestamp": f"{ts1} {ts2} {ts3} {ts4} {ts5}",
        "level": level,
        "message": msg,
    }


def parse_line(line):
    """
    Parses a single line of text.

    Strips any trailing whitespace characters and returns
    the cleaned line in a dictionary with the key 'line'.

    Args:
        line (str): The line of text to be parsed.

    Returns:
        dict: A dictionary containing the cleaned line with the key 'line'.
    """
    return {"line": line.rstrip()}


def parse_data(data):
    """
    Convert the input data to a string and return it within a dictionary.

    Args:
        data (any): The input data to be converted to a string.

    Returns:
        dict: A dictionary with the key 'data' and the value being the input data converted to a string.
    """
    return {"data": str(data)}


import shlex
import subprocess


def sh(command, **kwargs):
    """
    Execute a shell command and return its output.

    This function splits the command string into a list, executes it using subprocess.run,
    and returns the stripped stdout. It allows customization of all subprocess.run parameters.

    Args:
        command (str): The shell command to execute.
        **kwargs: Additional keyword arguments to pass to subprocess.run.

    Returns:
        str: The stripped stdout of the command if stdout was captured.
        subprocess.CompletedProcess: The full result object if stdout was not captured.

    Raises:
        subprocess.CalledProcessError: If the command returns a non-zero exit status and check=True.

    Default behavior:
        - Raises an exception if the command fails (check=True)
        - Captures and returns string output (text=True)
        - Captures both stdout and stderr (stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    Any of these defaults can be overridden by passing the corresponding keyword argument.
    """
    command_list = shlex.split(command)

    default_kwargs = {
        "check": True,
        "text": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
    }
    default_kwargs.update(kwargs)

    result = subprocess.run(command_list, **default_kwargs)

    # Return stripped stdout if available, otherwise return the CompletedProcess object
    return result.stdout.strip() if hasattr(result, "stdout") else result


# Make some modules available for use in filters and templates
EXPORTED_GLOBALS = build_globals_dict(
    [
        base64,
        collections,
        datetime,
        hashlib,
        itertools,
        json,
        math,
        pprint,
        random,
        re,
        string,
        textwrap,
        extract_json,
        extract_regex,
    ]
    + [create_extraction_function(regex) for regex in BUILTIN_REGEXES]
    + [
        format_datetime,
        guess_datetime,
        parse_kv,
        parse_logfmt,
        parse_jsonl,
        parse_clf,
        parse_combined,
        parse_unix,
        parse_line,
        parse_data,
        pprint_json,
        sh,
    ]
)


def list_exported_objects(ignore_underscore=True):
    funcs = EXPORTED_GLOBALS
    if ignore_underscore:
        funcs = [f for name, f in funcs.items() if not name.startswith("_")]
    return funcs


def print_json_elem(*myargs, **mykwargs):
    global is_first_visible_line
    if is_first_visible_line:
        is_first_visible_line = False
    else:
        print_output(args.output_event_sep, end="", **mykwargs)
    print_output(*myargs, end="", flush=True, **mykwargs)


def expand_color_codes(line):
    for _, (color, scolor) in COLOR_CODES.items():
        line = line.replace(scolor, color)
    return line


@dataclasses.dataclass
class Stats:
    # Sets would make this a few percent faster and simplify the implementation.
    # But we want to show items in their original order.
    keys: list
    loglevel_keys: list
    loglevels: list
    num_lines_seen: int
    num_events_shown: int
    first_timestamp: str
    last_timestamp: str
    timespan: str


class StoppedEarly(Exception):
    pass


def timedelta_from(duration):
    """
    Convert a duration string into a datetime.timedelta object.

    The duration string should be composed of numerical values followed by supported time units.
    For example: "5d" for 5 days, "3h30m" for 3 hours and 30 minutes, "2.5s" for 2.5 seconds.

    Supported time units are:
      - "us": microseconds
      - "ms": milliseconds (converted to microseconds internally)
      - "s": seconds
      - "m": minutes
      - "h": hours
      - "d": days
      - "w": weeks

    Args:
        duration (str): The duration string to be converted.

    Returns:
        datetime.timedelta: A timedelta object representing the duration.

    Raises:
        argparse.ArgumentTypeError: If the duration string is invalid or contains unsupported time units.
    """
    pattern = re.compile(r"([-\d.]+)([a-z]+)")
    matches = pattern.findall(duration)
    if not matches:
        raise argparse.ArgumentTypeError(f"Invalid timespec: {duration}")

    unit_map = {
        "us": "microseconds",
        "ms": "microseconds",  # timedelta argument, not description
        "s": "seconds",
        "m": "minutes",
        "h": "hours",
        "d": "days",
        "w": "weeks",
    }

    result = dt.timedelta()
    for value, unit in matches:
        value = float(value)
        if value < 0:
            raise argparse.ArgumentTypeError(
                f"Durations cannot be negative: {duration}"
            )

        if unit in unit_map:
            if unit == "ms":
                value *= 1000  # Convert milliseconds to microseconds
            result += dt.timedelta(**{unit_map[unit]: value})
        else:
            raise argparse.ArgumentTypeError(
                f"Unsupported time unit: '{unit}. Supported units: {', '.join(unit_map.keys())}"
            )

    return result


def format_ts_delta(timedelta):
    if timedelta is None:
        return "unknown"
    # XXX: better heuristics
    s = str(timedelta)
    if "." not in s:
        s += ".000000"
    return s


def add_ts_delta(event, last_ts_datetime):
    ts_datetime = get_timestamp_datetime(event)
    if last_ts_datetime is None:
        delta = ts_datetime
    else:
        delta = ts_datetime - last_ts_datetime
    last_ts_datetime = ts_datetime
    # Add to start of event dict so that delta is displayed first
    new_event = {"_klp_timedelta": format_ts_delta(delta)}
    new_event.update(event)
    return new_event, last_ts_datetime


def datetime_from(text):
    "Parse date given e.g. in command line arguments (localtime assumed)"
    midnight_today_localtime = (
        dt.datetime.now()
        .astimezone()
        .replace(hour=0, minute=0, second=0, microsecond=0)
    )
    midnight_today_utc = dt.datetime.now(tz=dt.timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    if text == "today":
        return midnight_today_localtime
    elif text == "tomorrow":
        return midnight_today_localtime + dt.timedelta(days=1)
    elif text == "yesterday":
        return midnight_today_localtime - dt.timedelta(days=1)
    elif text == "todayZ":
        return midnight_today_utc
    elif text == "tomorrowZ":
        return midnight_today_utc + dt.timedelta(days=1)
    elif text == "yesterdayZ":
        return midnight_today_utc - dt.timedelta(days=1)
    elif text == "now":
        return dt.datetime.now(tz=dt.timezone.utc)
    else:
        datetime = guess_datetime(text)
        if datetime is None:
            raise argparse.ArgumentTypeError(f"Not a valid timestamp: {text}")
        return datetime


datetime_converters = [
    # We don't want external dependencies like dateutil
    # military timezone (Z), very common for our K8s config
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    ),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    ),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    ),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc
    ),
    # XXX: datetime does not support nanoseconds, so we just treat them as 000
    lambda s: dt.datetime.strptime(s[:-4] + s[-1:], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    ),
    # usual timezone (+01:00), as we print with -z
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z"),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f%z"),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z"),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S%z"),
    # no timezone given (treat as localtime; for UTC, users could easily add Z)
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d %H:%M:%S").astimezone(),
    # XXX: datetime does not support nanoseconds, so we just treat them as 000
    lambda s: dt.datetime.strptime(
        s[:-4] + s[-1:], "%Y-%m-%dT%H:%M:%S.%f"
    ).astimezone(),
    # NCSA Common Log Format
    lambda s: dt.datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").astimezone(),
    # RFC 2822 (date -R)
    lambda s: dt.datetime.strptime(s, "%a, %d %b %Y %H:%M:%S %z").astimezone(),
    # With day name (git log)
    lambda s: dt.datetime.strptime(
        " ".join(s.split()[1:]), "%b %d %H:%M:%S %Y %z"
    ).astimezone(),
    # date -u
    lambda s: dt.datetime.strptime(
        " ".join(s.split()[1:]), "%b %d %H:%M:%S UTC %Y"
    ).replace(tzinfo=dt.timezone.utc),
    # only date
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y-%m").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y").astimezone(),
    lambda s: dt.datetime.strptime(s, "%Y %b %d %H:%M").astimezone(),
    # Assume current year if not given
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().year} {s}", "%Y %b %d %H:%M:%S.%f"
    ).astimezone(),
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().year} {s}", "%Y %b %d %H:%M:%S"
    ).astimezone(),
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().year} {s}", "%Y %b %d %H:%M"
    ).astimezone(),
    # Unix timestamps (seconds since epoch)
    lambda s: dt.datetime.fromtimestamp(float(s)),
    # Nginx timestamps (milliseconds since epoch)
    lambda s: dt.datetime.fromtimestamp(int(s) / 1000),
    # Android logs
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().year}-{s}", "%Y-%m-%d %H:%M:%S.%f"
    ).astimezone(),
    # Proxifier
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().year}.{s}", "%Y.[%m.%d %H:%M:%S]"
    ).astimezone(),
    # HealthApp
    lambda s: dt.datetime.strptime(s + "000", "%Y%m%d-%H:%M:%S:%f").astimezone(),
    # Zookeeper
    lambda s: dt.datetime.strptime(s + "000", "%Y-%m-%d %H:%M:%S,%f").astimezone(),
    # Apache
    lambda s: dt.datetime.strptime(s, "[%a %b %d %H:%M:%S %Y]").astimezone(),
    # Spark
    lambda s: dt.datetime.strptime(s, "%y/%m/%d %H:%M:%S").astimezone(),
    # BGL
    lambda s: dt.datetime.strptime(s, "%Y-%m-%d-%H.%M.%S.%f").astimezone(),
    # Wireshark
    lambda s: dt.datetime.strptime(s[:26], "%b %d, %Y %H:%M:%S.%f")
    .replace(microsecond=int(s[26:]) // 1000)
    .astimezone(),
]

dt_conv_order = list(range(len(datetime_converters)))


def now_rfc3339():
    return dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def to_datetime(timestamp):
    if timestamp is None:
        raise ValueError("No timestamp found.")
    datetime = guess_datetime(timestamp)
    if datetime is None:
        raise ValueError(
            f"Could not parse timestamp '{timestamp}'. Use --ts-format to specify the format. See --help-time for syntax help"
        )
    return datetime


def get_timestamp_datetime(event):
    if args.ts_key and args.ts_key in event:
        return to_datetime(event[args.ts_key])
    elif "timestamp" in event:
        return to_datetime(event["timestamp"])
    elif "ts" in event:
        return to_datetime(event["ts"])
    elif "time" in event:
        return to_datetime(event["time"])
    elif "t" in event:
        return to_datetime(event["t"])
    elif "at" in event:
        return to_datetime(event["at"])
    else:
        return None


def estr_or_none(val):
    if val is None:
        return None
    else:
        return EStr(val)


class EStr(str):
    def __init__(self, content):
        super().__init__()

    def __new__(cls, content):
        return super(EStr, cls).__new__(cls, content)

    def __add__(self, other):
        return estr_or_none(super().__add__(other))

    def __mul__(self, other):
        return estr_or_none(super().__mul__(other))

    def __getitem__(self, key):
        return estr_or_none(super().__getitem__(key))

    def upper(self):
        return estr_or_none(super().upper())

    def lower(self):
        return estr_or_none(super().lower())

    def capitalize(self):
        return estr_or_none(super().capitalize())

    def title(self):
        return estr_or_none(super().title())

    def swapcase(self):
        return estr_or_none(super().swapcase())

    def strip(self, chars=None):
        return estr_or_none(super().strip(chars))

    def lstrip(self, chars=None):
        return estr_or_none(super().lstrip(chars))

    def rstrip(self, chars=None):
        return estr_or_none(super().rstrip(chars))

    def split(self, sep=None, maxsplit=-1):
        return [estr_or_none(x) for x in super().split(sep, maxsplit)]

    def rsplit(self, sep=None, maxsplit=-1):
        return [estr_or_none(x) for x in super().rsplit(sep, maxsplit)]

    def join(self, iterable):
        return estr_or_none(super().join(iterable))

    def replace(self, old, new, count=-1):
        return estr_or_none(super().replace(old, new, count))

    def center(self, width, fillchar=" "):
        return estr_or_none(super().center(width, fillchar))

    def ljust(self, width, fillchar=" "):
        return estr_or_none(super().ljust(width, fillchar))

    def rjust(self, width, fillchar=" "):
        return estr_or_none(super().rjust(width, fillchar))

    def zfill(self, width):
        return estr_or_none(super().zfill(width))

    def partition(self, sep):
        a, b, c = super().partition(sep)
        return (EStr(a), EStr(b), EStr(c))

    def rpartition(self, sep):
        a, b, c = super().rpartition(sep)
        return (EStr(a), EStr(b), EStr(c))

    def format(self, *args, **kwargs):
        return estr_or_none(super().format(*args, **kwargs))

    def format_map(self, mapping):
        return estr_or_none(super().format_map(mapping))

    def slice(self, start, end=None):
        return estr_or_none(super().__getitem__(slice(start, end)))

    def casefold(self):
        return estr_or_none(super().casefold())

    def splitlines(self, keepends=False):
        return [estr_or_none(line) for line in super().splitlines(keepends)]

    def expandtabs(self, tabsize=8):
        return estr_or_none(super().expandtabs(tabsize))

    def col(self, n):
        """Extracts the nth column from the string.

        Args:
            n: Column number (0-based).

        Returns:
            The nth column of the string, or None if the column does not exist.
        """

        n = int(n)  # allow strings to be more consistent with cols()
        parts = self.split()
        if n < 0 or n >= len(parts):
            return None
        else:
            return estr_or_none(parts[n])

    def cols(self, *args, sep=None, outsep=" "):
        """Returns selected columns from the internal whitespace-separated string.

        This method extracts and optionally combines specific columns from the string stored in the EStr object.
        It supports both single column indexing and slicing.

        * Input arguments:
            * args: Accepts zero or more arguments representing column indices or slices.
                    If no arguments are provided, the entire string is returned.
                    If more than one argument is provided, returns a list
            * sep (optional): Delimiter used to separate columns in the internal string (defaults to whitespace).
                    Can be a compiled regex
            * outsep (optional): Delimiter used to join the selected columns (defaults to whitespace).

        * Column selection:
            * Supports single integer indices to select specific columns.
            * Supports colon-separated strings to define slices of columns.
            * Handles out-of-range or invalid integer inputs silently.

        * Output formatting:
            * Joins the selected columns using the specified outsep delimiter.

        Examples:

        >>> s = EStr("This is a test with 7 columns")
        >>> s.cols()  # Returns entire string by default
        ["This", "is", "a", "test", "with", "7", "columns"]
        >>> s.cols("0,3")  # Select columns 0 and 3 using a comma-separated string
        'This test'
        >>> s.cols(0, 3)  # Select columns 0 and 3 and return list
        'This test'
        >>> s.cols("1")  # Select column 1
        'is'
        >>> s.cols(1)  # Select column 1, equivalent to above
        'is'
        >>> s.cols("14")  # Attempt to select an out-of-range column 14
        ''
        >>> s.cols("1:3")  # Select a range of columns from 1 to 2 (end exclusive)
        'is a'
        >>> s.cols("-2,2,4:")  # Select columns using negative index and open-ended slice
        '7 a with 7 columns'
        >>> t = EStr("This|is a|test with|4 columns")
        >>> t.cols("1:3", sep="|")  # Specify a different column separator
        'is a|test with'
        >>> t.cols("-2,2,4:", sep="|", outsep=":")  # Specify both column and output separators
        'test with:test with'
        """

        result = []
        if isinstance(sep, re.Pattern):
            columns = re.split(sep, self)
        else:
            columns = self.split(sep)
        columns = [EStr(c) for c in columns]
        if not args:
            return columns

        for arg in args:
            # Split the input by commas for multiple indices or slices
            indices_list = str(arg).split(",")

            arg_result = []
            for index_or_slice in indices_list:
                if ":" in index_or_slice:  # It's a slice
                    parts = index_or_slice.split(":")

                    # Convert string parts to integers or None
                    # If there are less than 3 parts, fill the remaining with None
                    parts = [int(p) if p else None for p in parts] + [None] * (
                        3 - len(parts)
                    )

                    start, stop, step = parts
                    arg_result.extend(columns[slice(start, stop, step)])
                else:  # It's a single index
                    try:
                        idx = int(index_or_slice)
                        arg_result.append(columns[idx])
                    except (ValueError, IndexError):
                        # Ignore invalid or out-of-range integer inputs
                        pass
            result.append(outsep.join(arg_result))

        if len(args) > 1:
            return [EStr(elem) for elem in result]
        return estr_or_none(outsep.join(result))

    def extract_json(self):
        return estr_or_none(extract_json(self))

    def extract_regex(self, pattern, *groupargs):
        return estr_or_none(extract_regex(pattern, self, *groupargs))

    def format_datetime(self):
        return estr_or_none(format_datetime(self))

    def guess_datetime(self):
        return guess_datetime(self)

    def parse_kv(self, sep=None, kvsep="="):
        return parse_kv(self, sep, kvsep)

    def parse_logfmt(self):
        return parse_logfmt(self)

    def parse_jsonl(self):
        return parse_jsonl(self)

    def parse_clf(self):
        return parse_clf(self)

    def parse_combined(self):
        return parse_combined(self)

    def parse_unix(self):
        return parse_unix(self)

    def parse_line(self):
        return parse_line(self)

    def parse_data(self):
        return parse_data(self)

    def pprint_json(self, indent=2, sort_keys=True, ensure_ascii=False):
        return estr_or_none(pprint_json(self, indent, sort_keys, ensure_ascii))


def show(event, context_type="", lineno=None):
    event = reorder(event)
    if args.output_format == "default":
        if args.output_template:
            show_by_template(event, args.output_template)
        elif args.output_eval:
            show_by_eval_template(event, args.output_eval)
        else:
            show_default(event, context_type, lineno)
    elif args.output_format == "logfmt":
        show_logfmt(event)
    elif args.output_format == "jsonl":
        show_jsonl(event)
    elif args.output_format == "json":
        show_json(event)
    elif args.output_format in ("csv", "tsv", "psv"):
        show_csv(event, args.writer)
    elif args.output_format == "sqlite":
        write_sqlite(event, args.cursor)
    elif args.output_format == "extract":
        show_extract(event)


def escape_doublequotes_quoted(s):
    "Return string with unprintable chars (and double quotes) escaped"
    orig_repr = repr(s)
    if orig_repr.startswith('"') and orig_repr.endswith('"'):
        return orig_repr[1:-1].replace("\\'", "'")
    elif orig_repr.startswith("'") and orig_repr.endswith("'"):
        return orig_repr[1:-1].replace('"', '\\"')


def escape_plain(s):
    "Return string with unprintable chars escaped"
    return repr(s)[1:-1]


def unescape(s):
    return re.sub(
        r'\\(?:([\\abfnrtv"])|x([0-9a-fA-F]{2}))',
        lambda m: {
            "\\": "\\",
            "a": "\a",
            "b": "\b",
            "f": "\f",
            "n": "\n",
            "r": "\r",
            "t": "\t",
            "v": "\v",
            '"': '"',  # Handle escaped double quotes
        }.get(m.group(1), chr(int(m.group(2), 16)) if m.group(2) else ""),
        s,
    )


def show_json(event, ensure_ascii=False):
    print_json_elem(json.dumps(event, ensure_ascii=ensure_ascii))


def show_jsonl(event, ensure_ascii=False):
    print_output(json.dumps(event, ensure_ascii=ensure_ascii))


def show_by_template(event, template):
    template = template.replace("\\n", "\n").replace("\\t", "\t")
    try:
        out = template.format(**event)
        print_output(out, end=args.output_event_sep)
    except KeyError:
        pass


def show_by_eval_template(event, template):
    template = template.replace("\\n", "\n").replace("\\t", "\t")
    # Find {expression} patterns
    pattern = re.compile(r"\{(.*?)\}")

    # Replace each match with its evaluated result
    def replace_expr(match):
        expr = match.group(1)
        event_plus_underscore = event.copy()
        event_plus_underscore["_"] = event
        try:
            return str(eval(expr, EXPORTED_GLOBALS, event_plus_underscore))
        except Exception as e:
            if args.debug or args.debug_eval:
                print(f"[Error evaluating {expr!r}: {e}. {event=}]", file=sys.stderr)
            return None

    # Replace all expressions in the template
    out = pattern.sub(replace_expr, template)
    if out:
        print_output(out, end=args.output_event_sep)


def show_csv(event, writer):
    cols = []
    for key in args.keys:
        cols.append(escape_plain(event.get(key, "")))
    writer.writerow(cols)


def write_sqlite(event, cursor):
    cols = []
    for key in args.keys:
        cols.append(escape_plain(event.get(key, "")))
    placeholders = ", ".join(["?" for _ in args.keys])
    cursor.execute(f"INSERT INTO data VALUES ({placeholders})", cols)


def show_default(event, context_type="", lineno=None):
    colors = THEMES[args.theme]["context_prefix"]
    context_prefix = {
        "before": scolorize("/ ", colors["before"]),
        "match": scolorize("* ", colors["match"]),
        "after": scolorize("\\ ", colors["after"]),
        "fuse_first": scolorize("1 ", colors["fuse_first"]),
        "fuse_last": scolorize(f"{lineno} ", colors["fuse_last"]),
    }.get(context_type, "")

    if args.each_key:
        # One part per item
        parts = [{key: val} for key, val in event.items()]
    else:
        # Only one part
        parts = [event]

    out = []
    for part in parts:
        elems = []
        for key, val in part.items():
            key_lower = key.lower()
            val = str(val)
            double_quotes_needed = args.output_quoting == csv.QUOTE_ALL or (
                not args.plain
                and args.output_quoting != csv.QUOTE_NONE
                and RE_WHITESPACE.search(val)
            )
            val = (
                escape_doublequotes_quoted(val)
                if double_quotes_needed
                else escape_plain(val)
            )

            key_color = THEMES[args.theme]["keys"]
            quote_color = THEMES[args.theme]["quotes"]
            val_color = ""
            if key_lower in TS_KEYS:
                val_color = THEMES[args.theme]["timestamp_key"]
                val = format_datetime(val)
            elif key_lower in LEVEL_KEYS:
                val_color = THEMES[args.theme]["levels"].get(val.lower(), "off")
            elif key_lower in MSG_KEYS:
                val_color = THEMES[args.theme]["message_key"]

            if args.color:
                if args.plain:
                    elems.append(SCOLOR["off"] + scolorize(val, val_color))
                elif double_quotes_needed:
                    elems.append(
                        SCOLOR["off"]
                        + scolorize(key, key_color)
                        + scolorize('="', quote_color)
                        + scolorize(val, val_color)
                        + scolorize('"', quote_color)
                    )
                else:
                    elems.append(
                        SCOLOR["off"]
                        + scolorize(key, key_color)
                        + scolorize("=", quote_color)
                        + scolorize(val, val_color)
                    )
            else:
                if args.plain:
                    elems.append(f"{val}")
                elif double_quotes_needed:
                    elems.append(f'{key}="{val}"')
                else:
                    elems.append(f"{key}={val}")

        text = args.output_sep.join(elems)
        val_lines = RE_EOL_OR_TAB.split(text) if args.expand else [text]
        for v, text in enumerate(val_lines):
            indent = ""
            if context_prefix and v == 0 and part == parts[0]:
                text = context_prefix + text
                context_indent = "  "
            else:
                context_indent = ""
            if args.output_width:
                text = text[: args.output_width]
            if part != parts[0]:
                indent += "  "
            if args.expand and v > 0:
                indent += "    "
            if args.output_wrap:
                for line in textwrap.wrap(
                    text,
                    width=args.output_wrap,
                    initial_indent=indent,
                    subsequent_indent=indent + context_indent + "  ",
                ):
                    if line:
                        out.append(line)
            else:
                out.append(text)
    for line in out:
        if args.color:
            print_output(expand_color_codes(line), end=args.output_event_sep)
        else:
            print_output(line, end=args.output_event_sep)


def show_logfmt(event):
    elems = []
    for key, val in event.items():
        val = str(val)
        double_quotes_needed = not args.plain and RE_WHITESPACE.search(str(val))
        val = (
            escape_doublequotes_quoted(val)
            if double_quotes_needed
            else escape_plain(val)
        )
        if key.lower() in TS_KEYS:
            val = format_datetime(val)

        if args.plain:
            elems.append(f"{val}")
        elif double_quotes_needed:
            elems.append(f'{key}="{val}"')
        else:
            elems.append(f"{key}={val}")

    line = " ".join(elems)
    print_output(line)


def show_extract(event):
    if args.grep_by_key:
        for key, pattern in args.grep_by_key.items():
            if key in event:
                matches = pattern.findall(event.get(key), "")
                if matches:
                    for match in matches:
                        print(match[0])
    elif args.grep:
        for pattern in args.grep:
            matches = pattern.findall(make_greppable(event))
            if matches:
                for match in matches:
                    print(match[0])


def print_err(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def colorize(text, color):
    if args.color and color:
        return COLOR[color] + text + COLOR["off"]
    else:
        return text


def scolorize(text, color):
    if args.color and color:
        return SCOLOR[color] + text + SCOLOR["off"]
    else:
        return text


def colorize_loglevels(keys):
    return [
        colorize(key, THEMES[args.theme]["levels"].get(key.lower(), "off"))
        for key in keys
    ]


def show_stats(stats):
    if args.color:
        print_err(COLOR["off"], end="")
    colors = THEMES[args.theme]
    seen = stats.num_lines_seen
    shown = stats.num_events_shown
    if seen > 0 and shown > 0:
        percent = f" ({shown/seen:.0%} of { seen } lines seen)"
    else:
        percent = ""
    print_err(f"Events shown: { shown }{percent}")
    if stats.first_timestamp:
        try:
            span = to_datetime(stats.last_timestamp) - to_datetime(
                stats.first_timestamp
            )
            total_seconds = span.total_seconds()
            rate_info = (
                f", {shown/total_seconds:.1f} events/s" if total_seconds > 0 else ""
            )
            spanstr = f" ({ span }{ rate_info })"
        except ValueError:
            spanstr = ""
        print_err(
            f"Time span shown: { colorize(format_datetime(stats.first_timestamp), colors['timestamp_key']) } "
            f"to { colorize(format_datetime(stats.last_timestamp), colors['timestamp_key']) }",
            spanstr,
        )
    print_err(
        f"Keys seen: { ','.join( colorize(key, colors['keys']) for key in stats.keys)}"
    )
    print_err(
        f"Log levels seen: { ','.join(colorize_loglevels(stats.loglevels))}"
        f" (keys: {','.join(stats.loglevel_keys)})"
    )


def show_stats_json(stats, ensure_ascii=False):
    print_err(
        json.dumps(dataclasses.asdict(stats), indent=2, ensure_ascii=ensure_ascii)
    )


def update_stats(stats, event):
    global args
    # Don't compute stats when not needed. Improves performance
    if not (args.stats or args.stats_only or args.max_events or args.timespan):
        return stats
    stats.num_events_shown += 1
    # We cannot use sets because they cannot be converted into JSON
    for key in event:
        if key not in stats.keys:
            stats.keys.append(key)
    loglevel_key, loglevel = get_log_level(event)
    if loglevel_key and loglevel_key not in stats.loglevel_keys:
        stats.loglevel_keys.append(loglevel_key)
    if loglevel and loglevel not in stats.loglevels:
        stats.loglevels.append(loglevel)
    ts = get_timestamp_str_or_none(event)
    if ts:
        # FIXME: This string comparison only works for ISO dates
        if stats.first_timestamp == "" or ts < stats.first_timestamp:
            stats.first_timestamp = ts
            if args.timespan is not None:
                try:
                    temp = to_datetime(stats.first_timestamp) + args.timespan
                    if args.to_dt is None:
                        args.to_dt = temp
                    else:
                        args.to_dt = min(temp, args.to_dt)
                except ValueError as e:
                    print_err(f"Error parsing timestamp: {e}")
        stats.last_timestamp = ts
    return stats


def get_timestamp_str_or_none(event):
    if args.ts_key:
        return event.get(args.ts_key, None)
    else:
        return (
            event.get("timestamp", None)
            or event.get("ts", None)
            or event.get("time", None)
            or event.get("at", None)
            or event.get("t", None)
        )


def get_log_level(event):
    for key in LEVEL_KEYS:
        try:
            return key, event[key]
        except KeyError:
            continue
    return None, None


def key_matches(regex, key, event):
    val = event.get(key, "")
    if val and regex.search(val):
        return True
    return False


def matches_python_expr(expr, event):  #
    event = {k: v for k, v in event.items()}
    event_plus_underscore = event.copy()
    event_plus_underscore["_"] = event
    try:
        return eval(expr, EXPORTED_GLOBALS, event_plus_underscore)
    except Exception as e:
        if args.debug or args.debug_where:
            print(f"[Error matching {expr}: {e}. event={event}]", file=sys.stderr)
        return False


def make_greppable(event):
    return " ".join(f'{k}="{v}"' for k, v in event.items())


def visible(event):
    if (
        (
            args.grep_not
            and any(regex.search(make_greppable(event)) for regex in args.grep_not)
        )
        or (
            args.grep
            and not any(regex.search(make_greppable(event)) for regex in args.grep)
        )
        or (args.where and not matches_python_expr(args.where, event))
    ):
        return False

    if not event:
        return False

    if (
        args.grep_not_by_key
        and any(
            key_matches(regex, key, event)
            for key, regex in args.grep_not_by_key.items()
        )
    ) or (
        args.grep_by_key
        and not any(
            key_matches(regex, key, event) for key, regex in args.grep_by_key.items()
        )
    ):
        return False

    try:
        if args.from_dt is not None or args.to_dt is not None:
            dt_event = get_timestamp_datetime(event)
            if dt_event is not None:
                if args.from_dt is not None and dt_event < args.from_dt:
                    return False
                if args.to_dt is not None and dt_event > args.to_dt:
                    if len(args.files) < 2:
                        raise StoppedEarly
                    return False
    except ValueError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)

    if args.loglevels or args.loglevels_not:
        _, level = get_log_level(event)
        if level is not None:
            level = level.lower()
            if (args.loglevels_not and level in args.loglevels_not) or (
                args.loglevels and level not in args.loglevels
            ):
                return False
    # Regard events with no selected keys as invisible
    if not reorder(event):
        return False
    return True


def reorder(event):
    """Reorder event keys in the order given on the command-line
    and remove unwanted keys"""
    return {
        key: event[key]
        for key in args.keys or event.keys()
        if key in event and key not in args.keys_not
    }


def input_exec(code, event):
    def exec_and_get_locals(code, local_vars):
        local_vars = local_vars or {}
        exec(code, EXPORTED_GLOBALS, local_vars)
        return local_vars

    def remove_underscores(event):
        return {
            key: val
            for key, val in event.items()
            if val is not None and key not in ("_", "__", "___")
        }

    # Allow special methods on String
    local_vars = {key: EStr(val) for key, val in event.items()}
    # Make event available via underscore to allow keys that are not valid Python variable names (e.g. "req.method")
    local_vars["_"] = event
    try:
        event = exec_and_get_locals(code, local_vars)

        if "___" in event:  # Multiple output events
            result = [ev for ev in event["___"] if ev is not None]
        elif "__" in event:  # One output event
            merged_event = {**event, **event["__"]}
            del merged_event["__"]
            result = [remove_underscores(merged_event)]
        else:  # No special output
            result = [remove_underscores(event)]
    except Exception as e:
        if args.debug or args.debug_eval:
            print(
                f"[Error executing {args.input_exec!r}: {e}. {event=}]",
                file=sys.stderr,
            )
        result = []
    return result


def extract_key_regex(spec):
    m = RE_EXTRACT_KEY.match(spec)
    if m:
        return m.group(1), m.group(2)
    return None, spec


def make_regex_dict(specs):
    result = {}
    new_specs = []
    for spec in specs:
        key, regex = extract_key_regex(spec)
        if key:
            result[key] = regex
        else:
            new_specs.append(spec)
    return result, new_specs


def quoting_type(text):
    return {
        "minimal": csv.QUOTE_MINIMAL,
        "all": csv.QUOTE_ALL,
        "nonnumeric": csv.QUOTE_NONNUMERIC,
        "none": csv.QUOTE_NONE,
    }.get(text, None)


def csv_type(text):
    return [] if text is None else text.split(",")


def csv_lower_type(text):
    return csv_type(text.lower())


def builtin_regex(text):
    if "~" in text:
        key, regex = text.split("~", 1)
        prefix = key + "~"
    else:
        regex = text
        prefix = ""
    try:
        return [prefix + b for b in BUILTIN_REGEXES[regex]]
    except KeyError:
        raise argparse.ArgumentTypeError(
            f"'{regex}' is not a builtin regex {list(BUILTIN_REGEXES)}"
        )


def positive_int(value):
    try:
        ivalue = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid value '{value}'. Must be a positive integer or zero."
        )
    if ivalue < 0:
        raise argparse.ArgumentTypeError(
            f"Invalid value '{value}'. Must be a positive integer or zero."
        )
    return ivalue


def flatten_sublists(li):
    return [item for sublist in li for item in sublist]


def get_function_signature(func):
    try:
        sig = inspect.signature(func)
        params = []
        for name, param in sig.parameters.items():
            if param.default is param.empty:
                params.append(name)
            else:
                params.append(f"{name}={param.default!r}")
        return f"({', '.join(params)})"
    except ValueError:
        return "()"


def print_python_help(terminal_width=80):
    exported_objects = list_exported_objects(ignore_underscore=True)

    def get_signature(obj):
        try:
            return str(inspect.signature(obj))
        except ValueError:
            return "(...)"  # fallback for built-ins without accessible signatures

    # Separate modules and functions
    modules = [obj for obj in exported_objects if inspect.ismodule(obj)]
    functions = [
        obj
        for obj in exported_objects
        if inspect.isfunction(obj) or inspect.ismethod(obj)
    ]

    # Handle modules
    max_module_name_length = max(len(obj.__name__) for obj in modules)
    print("Modules:")
    for obj in modules:
        try:
            doc = obj.__doc__.splitlines()[0] if obj.__doc__ else ""
        except AttributeError:
            doc = ""
        print(f"  {obj.__name__.ljust(max_module_name_length + 2)} {doc}")

    print("Functions:")
    for obj in list_exported_objects():
        if inspect.isfunction(obj) or inspect.isbuiltin(obj):
            name = obj.__name__
            signature = get_signature(obj)
            doc = obj.__doc__.split("\n")[0] if obj.__doc__ else "No docstring"

            full_info = f" {name}{signature} - {doc}"
            if len(full_info) > terminal_width:
                doc_part = full_info[-(terminal_width - 3) :]
                full_info = f" {name}{signature} -...{doc_part}"

            print(full_info)


def print_time_format_help():
    help_text = """
Time Format Reference:
%Y - Year with century as a decimal number (e.g., 2024)
%y - Year without century as a zero-padded decimal number (00-99)
%m - Month as a zero-padded decimal number (01-12)
%b - Month as locale's abbreviated name (e.g., Jan, Feb, ..., Dec)
%B - Month as locale's full name (e.g., January, February, ..., December)
%d - Day of the month as a zero-padded decimal number (01-31)
%j - Day of the year as a zero-padded decimal number (001-366)
%H - Hour (24-hour clock) as a zero-padded decimal number (00-23)
%I - Hour (12-hour clock) as a zero-padded decimal number (01-12)
%p - Locale's equivalent of either AM or PM
%M - Minute as a zero-padded decimal number (00-59)
%S - Second as a zero-padded decimal number (00-59)
%f - Microsecond as a decimal number, zero-padded on the left (000000-999999)
%z - UTC offset in the form ±HHMM[SS[.ffffff]] (empty string if naive)
%Z - Time zone name (e.g, UTC, GMT, CEST, empty string if naive)
%w - Weekday as a decimal number, where 0 is Sunday and 6 is Saturday
%a - Weekday as locale's abbreviated name (Sun, Mon, ..., Sat)
%A - Weekday as locale's full name (Sunday, Monday, ..., Saturday)
%W - Week number of the year (Monday as the first day of the week)
%U - Week number of the year (Sunday as the first day of the week)

For a complete list of format codes, refer to https://strftime.org or the Python docs:
https://docs.python.org/3/library/datetime.html#strftime-and-strptime-format-codes
    """
    print(help_text)


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
        epilog=EPILOG,
    )
    parser.add_argument(
        "files",
        metavar="FILE",
        nargs="*",
        help="files to read, if empty, stdin is used",
    )

    input = parser.add_argument_group("input options")
    input.add_argument(
        "--input-format",
        "-f",
        choices=[
            "logfmt",
            "jsonl",
            "json",
            "csv",
            "tsv",
            "psv",
            "table",
            "clf",
            "combined",
            "unix",
            "line",
            "data",
            "sqlite",
            "ts1m",
            "ts1lm",
            "ts2m",
            "ts2lm",
            "ts3m",
            "ts3lm",
            "ts4m",
            "ts4lm",
            "ts5m",
            "ts5lm",
        ],
        default="logfmt",
        help="format of the input data. Default: logfmt. csv, tsv and psv need a header line. json cannot be streamed. clf is NCSA Common Log Format. combined is Extended Apache. data reads whole file",
    )
    input.add_argument(
        "--jsonl-input", "-j", action="store_true", help="input format is JSON Lines"
    )
    input.add_argument(
        "--logical-lines",
        action="store_true",
        help="handle indentation and backslash continuations to identify logical lines",
    )
    input.add_argument(
        "--input-encoding",
        default="utf-8",
        help="Text encoding of the input data. Default: utf-8",
    )
    input.add_argument(
        "--no-header",
        action="store_false",
        dest="has_header",
        help="CSV/TSV/PSV has no header. Will auto-generate numbered column keys",
    )
    input.add_argument(
        "--input-delimiter",
        help="CSV/TSV/PSV input delimiter",
    )
    input.add_argument(
        "--input-quoting",
        choices=["minimal", "all", "nonnumeric", "none"],
        default="minimal",
        help="CSV/TSV/PSV quoting used for input format. Default: minimal",
    )
    input.add_argument(
        "--input-tablename",
        metavar="TABLENAME",
        help="SQLite table name to read data from. Needed when more than 1 table exists",
    )
    input.add_argument(
        "--input-exec",
        "-I",
        metavar="CODE",
        default=[],
        action="append",
        help="execute Python code to transform event after input parsing",
    )

    selection = parser.add_argument_group("event selection options")
    selection.add_argument(
        "--loglevels",
        "-l",
        metavar="LEVELS",
        type=csv_lower_type,
        help="comma-separated names of loglevels to process (case-insensitive). Use -S to show the loglevels available",
    )
    selection.add_argument(
        "--loglevels-not",
        "-L",
        metavar="LEVELS",
        type=csv_lower_type,
        help="comma-separated names of loglevels NOT to process (case-insensitive)",
    )
    selection.add_argument(
        "--skip",
        metavar="NUM",
        type=int,
        help="don't process the first N number of lines",
    )

    grep = parser.add_argument_group(
        "event selection by regular expression (grepping) options"
    )
    grep.add_argument(
        "--grep",
        "-g",
        metavar="REGEX",
        default=[],
        action="append",
        help="only process lines matching the given REGEX. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will allow the line to be processed",
    )
    grep.add_argument(
        "--grep-not",
        "-G",
        "-v",
        metavar="REGEX",
        default=[],
        action="append",
        help="don't process lines matching REGEX. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will exclude the line from processing",
    )
    grep.add_argument(
        "--grep-builtin",
        "-r",
        metavar="REGEX",
        type=builtin_regex,
        default=[],
        action="append",
        help=f"only process lines according to one of the built-in regexes {list(BUILTIN_REGEXES)}. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will allow the line to be processed",
    )
    grep.add_argument(
        "--grep-builtin-not",
        "-R",
        metavar="REGEX",
        type=builtin_regex,
        default=[],
        action="append",
        help=f"don't process lines according to one of the built-in regexes {list(BUILTIN_REGEXES)}. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will allow the line to be processed",
    )
    grep.add_argument(
        "--start-after",
        metavar="REGEX",
        default=[],
        action="append",
        help="start processing events after a line matching REGX has been found",
    )
    grep.add_argument(
        "--start-with",
        metavar="REGEX",
        default=[],
        action="append",
        help="start processing events when a line matching REGEX is found",
    )
    grep.add_argument(
        "--stop-with",
        metavar="REGEX",
        default=[],
        action="append",
        help="stop processing events after a line matching REGEX is found",
    )
    grep.add_argument(
        "--stop-before",
        metavar="REGEX",
        default=[],
        action="append",
        help="stop processing events when a line matching REGEX is found",
    )
    grep.add_argument(
        "--num-blocks",
        metavar="NUM",
        default=1,
        type=int,
        help="stop processing after NUM start/stop blocks (default: 1, unlimited: -1)",
    )
    grep.add_argument(
        "--ignore-case",
        "-i",
        action="store_true",
        help="case-insensitive matching for all grep regexes",
    )
    grep.add_argument(
        "--where",
        metavar="EXPR",
        default="",
        help="only process lines where the given Python expression is True",
    )
    grep.add_argument(
        "--before-context",
        "-B",
        type=positive_int,
        default=0,
        metavar="NUM",
        help="print NUM lines of leading context before each matching event",
    )
    grep.add_argument(
        "--after-context",
        "-A",
        type=positive_int,
        default=0,
        metavar="NUM",
        help="print NUM lines of trailing context after each matching event",
    )
    grep.add_argument(
        "--context",
        "-C",
        type=positive_int,
        default=0,
        metavar="NUM",
        help="print NUM lines of  context before and after each matching event",
    )

    time_selection = parser.add_argument_group("event selection by time")
    time_selection.add_argument(
        "--ts-key",
        metavar="KEY",
        help="parse timestamp from KEY",
    )
    time_selection.add_argument(
        "--ts-format",
        metavar="FORMAT",
        help="add FORMAT to the list of timestamp formats to try",
    )
    time_selection.add_argument(
        "--from",
        dest="from_dt",
        type=datetime_from,
        metavar="ISODATETIME",
        help="show only lines for which timestamp is ISODATETIME or later."
        " Also: 'now', 'today', 'yesterday', 'tomorrow' (midnight localtime). Use 'todayZ' etc. for UTC.",
    )
    time_selection.add_argument(
        "--to",
        dest="to_dt",
        type=datetime_from,
        metavar="ISODATETIME",
        help="show only lines for which timestamp is ISODATETIME or earlier."
        " Also: 'now', 'today', 'yesterday', 'tomorrow' (midnight localtime). Use 'todayZ' etc. for UTC.",
    )
    time_selection.add_argument(
        "--since",
        metavar="INTERVAL",
        type=timedelta_from,
        help="show only lines for which timestamp is less than INTERVAL ago.",
    )
    time_selection.add_argument(
        "--until",
        metavar="INTERVAL",
        type=timedelta_from,
        help="show only lines for which timestamp is less than INTERVAL in the future.",
    )
    time_selection.add_argument(
        "--new", "-n", action="store_true", help="only print new lines (--since 0s)"
    )
    time_selection.add_argument(
        "--duration",
        "-d",
        metavar="INTERVAL",
        type=timedelta_from,
        help="show only lines for which timestamp is less than INTERVAL after program start or time given by --from/--since)",
    )
    time_selection.add_argument(
        "--timespan",
        metavar="INTERVAL",
        type=timedelta_from,
        help="show only lines for which timestamp is less than INTERVAL after time of first event",
    )

    output = parser.add_argument_group("output format options")
    output.add_argument(
        "--output-format",
        "-F",
        choices=[
            "default",
            "logfmt",
            "jsonl",
            "json",
            "csv",
            "tsv",
            "psv",
            "sqlite",
            "extract",
        ],
        default="default",
        help="format of the output data. Default: default. logfmt is plain logfmt, without colors or formatting",
    )
    output.add_argument(
        "--jsonl-output", "-J", action="store_true", help="output in JSON Lines format"
    )
    output.add_argument(
        "--output-encoding",
        default="utf-8",
        help="Text encoding for the output. Default: utf-8",
    )
    output.add_argument(
        "--output-delimiter",
        help="CSV/TSV/PSV output delimiter",
    )
    output.add_argument(
        "--output-quoting",
        choices=["minimal", "all", "nonnumeric", "none"],
        default="minimal",
        help="quoting used for output format. Default: minimal",
    )
    output.add_argument(
        "--output-tablename",
        metavar="TABLENAME",
        default="data",
        help="SQLite table to write data to. Default: data",
    )
    output.add_argument(
        "--max-events",
        "-m",
        metavar="NUM",
        type=int,
        help="maximum number of events to show",
    )
    output.add_argument(
        "--common",
        "-c",
        action="store_true",
        help="show timestamp, log level and message. Activates --plain, --indent and --unicode",
    )
    output.add_argument(
        "--keys",
        "-k",
        metavar="KEYS",
        default=[],
        type=csv_type,
        help="comma-separated names of keys to display (default: all). Use -S to show available keys",
    )
    output.add_argument(
        "--keys-not",
        "-K",
        metavar="KEYS",
        default=[],
        type=csv_type,
        help="comma-separated names of keys NOT to display",
    )
    output.add_argument(
        "--no-plain", "-P", action="store_true", help="don't display values only"
    )
    output.add_argument(
        "--unicode",
        "-u",
        action="store_true",
        help="use unicode symbols to simplify/beautify output by replacing characters",
    )
    output.add_argument(
        "--no-unicode",
        "-U",
        action="store_true",
        help="don't use unicode symbols to simplify/beautify output by replacing characters",
    )
    output.add_argument(
        "--output-file",
        "-o",
        metavar="PATH",
        help="write output to given file. Deactivates color unless explicitly requested. Default: stdout",
    )

    default_output = parser.add_argument_group("default output format options")
    default_output.add_argument(
        "--plain", "-p", action="store_true", help="display values only"
    )
    default_output.add_argument(
        "--indent",
        action="store_true",
        help="wrap at terminal width and indent subsequent lines",
    )
    default_output.add_argument(
        "--no-indent",
        action="store_true",
        help="don't wrap at terminal width and don't indent subsequent lines",
    )
    default_output.add_argument(
        "--each-key",
        "-e",
        action="store_true",
        help="print each key on a separate line",
    )
    default_output.add_argument(
        "--no-wrap",
        "-W",
        action="store_true",
        help="limit output to terminal width. Text is cut there to prevent wrapping",
    )
    default_output.add_argument(
        "--localtime",
        "-z",
        action="store_true",
        help="output timestamps with local timezone (decreases performance)",
    )
    default_output.add_argument(
        "--utc",
        "-Z",
        action="store_true",
        help="output timestamps with UTC timezone (decreases performance)",
    )
    default_output.add_argument(
        "--no-color",
        action="store_true",
        help="no ANSI colors. Alternatively, set the NO_COLOR environment variable.",
    )
    default_output.add_argument(
        "--color",
        action="store_true",
        help="always use ANSI colors, even when output is not to a TTY (e.g. to a pipe)",
    )
    default_output.add_argument(
        "--theme",
        choices=THEMES.keys(),
        default=list(THEMES.keys())[0],
        help=f"use these color palette and style. Default: {list(THEMES.keys())[0]}",
    )
    default_output.add_argument(
        "--expand",
        "-E",
        action="store_true",
        help="split values at \\n and \\t characters and show on separate lines",
    )
    default_output.add_argument(
        "--output-sep",
        metavar="STR",
        default=" ",
        help="string to separate fields",
    )
    default_output.add_argument(
        "--output-event-sep",
        metavar="STR",
        default="\n",
        help="string to separate events. Default: newline",
    )
    default_output.add_argument(
        "--output-template",
        metavar="STR",
        default="",
        help='Python f-string template for output, e.g. "{timestamp} {message}"',
    )
    default_output.add_argument(
        "--output-eval",
        metavar="STR",
        default="",
        help='''Python eval template for output, e.g. "{ts} {level.upper()} {'#'*len(msg)}"''',
    )
    default_output.add_argument(
        "--header",
        metavar="STR",
        help="string to print before first element",
    )
    default_output.add_argument(
        "--footer",
        metavar="STR",
        help="string to print before first event",
    )

    output_special = parser.add_argument_group("special output format options")
    output_special.add_argument(
        "--stats",
        "-s",
        action="store_true",
        help="print statistics to stderr, in addition to regular output",
    )
    output_special.add_argument(
        "--stats-only",
        "-S",
        action="store_true",
        help="print statistics only (to stderr)",
    )
    output_special.add_argument(
        "--levelmap",
        "-M",
        action="store_true",
        help="output first char of log levels only to give a big picture overview",
    )
    output_special.add_argument(
        "--keymap",
        metavar="KEY",
        help="output first char the given key only to give a big picture overview",
    )
    output_special.add_argument(
        "--mark-gaps",
        metavar="INTERVAL",
        type=timedelta_from,
        help="between events that are separated by more than INTERVAL,"
        " show a marker that visually separates them.",
    )
    output_special.add_argument(
        "--extract",
        "-x",
        metavar="REGEX",
        type=builtin_regex,
        default=[],
        action="append",
        help=f"extract text matching one of the built-in regexes {list(BUILTIN_REGEXES)}. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will allow the line to be processed",
    )
    output_special.add_argument(
        "--fuse",
        metavar="INTERVAL",
        type=timedelta_from,
        help="for a sequence of events that are separated by less than INTERVAL,"
        " show only the first and last.",
    )
    output_special.add_argument(
        "--debug",
        action="store_true",
        help="print exceptions",
    )

    output_special.add_argument(
        "--debug-where",
        action="store_true",
        help="print exceptions when evaluating --where expressions",
    )

    output_special.add_argument(
        "--debug-eval",
        action="store_true",
        help="print exceptions when evaluating --output-eval expressions",
    )

    other = parser.add_argument_group("other options")
    other.add_argument(
        "--selftest",
        action="store_true",
        help="run tests",
    )
    other.add_argument(
        "--version",
        action="version",
        version="%(prog)s v" + __version__,
        help="show version number",
    )
    other.add_argument(
        "--help-python",
        action="store_true",
        help="show modules and functions available for Python expressions/code (apart from builtins)",
    )
    other.add_argument(
        "--help-time", action="store_true", help="Print time format reference"
    )
    other.add_argument(
        "-h", "--help", action="help", help="show this help message and exit"
    )

    args = parser.parse_args()

    if args.help_python:
        print_python_help(terminal_width)
        sys.exit(0)

    if args.help_time:
        print_time_format_help()
        sys.exit(0)

    if sys.stdin.isatty() and not args.files and not args.selftest:
        parser.print_usage()
        sys.exit(0)

    args.color = (
        args.color
        or (not args.output_file and sys.stdout.isatty())
        and not (args.no_color or "NO_COLOR" in os.environ)
    )

    args.input_quoting = quoting_type(args.input_quoting)
    args.output_quoting = quoting_type(args.output_quoting)
    if args.output_file:
        try:
            args.output_file = open(
                args.output_file, "w", encoding=args.output_encoding
            )
        except FileNotFoundError:
            print("Could not open output file for writing:", repr(args.output_file))
            sys.exit(1)
    else:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=args.output_encoding)
        args.output_file = sys.stdout

    if args.jsonl_input:
        args.input_format = "jsonl"
    if args.jsonl_output:
        args.output_format = "jsonl"

    delimiter_defaults = {"csv": ",", "tsv": "\t", "psv": "|"}
    if args.input_format in ["csv", "tsv", "psv"]:
        if args.input_delimiter is None:
            args.input_delimiter = delimiter_defaults.get(args.input_format)

    if args.output_format in ["csv", "tsv", "psv"]:
        if not args.keys:
            print_err(
                "CSV, TSV or PSV format needs explicit list of keys. Use -S to list and copy them, then rerun with -k."
            )
            sys.exit(1)
        # Delimiter defaults by filetype
        if args.output_delimiter is None:
            args.output_delimiter = delimiter_defaults.get(args.output_format)
        args.writer = csv.writer(
            args.output_file,
            delimiter=args.output_delimiter,
            quoting=args.output_quoting,
        )
    args.cursor = None
    if args.output_format == "sqlite":
        if not args.output_file:
            print_err("SQLite format needs output file")
            sys.exit(1)
        if not args.keys:
            print_err(
                "SQLite format needs explicit list of keys. Use -S to list and copy them, then rerun with -k."
            )
            sys.exit(1)
        args.conn = sqlite3.connect(args.output_file.name)
        args.cursor = args.conn.cursor()
        # Create table based on keys
        columns = ", ".join([f'"{key}" TEXT' for key in args.keys])
        ensure_safe_tablename(args.output_tablename)
        query = f"CREATE TABLE IF NOT EXISTS {args.output_tablename} ({columns})"
        args.cursor.execute(query)

    args.add_ts = "_klp_ts" in args.keys
    args.add_ts_delta = "_klp_timedelta" in args.keys

    global TS_KEYS
    if args.ts_key:
        # XXX: Don't modify what looks like a constant
        TS_KEYS.append(args.ts_key)

    if args.common:
        args.keys = TS_KEYS + LEVEL_KEYS + MSG_KEYS + args.keys
        args.plain = True
        args.unicode = True
        args.indent = True

    if args.no_plain:
        args.plain = False
    if args.no_unicode:
        args.unicode = False
    if args.no_indent:
        args.indent = False

    if args.localtime and args.utc:
        print_err("Choose either localtime or UTC")
        sys.exit(1)

    if args.extract:
        args.grep_builtin = args.extract
        args.output_format = "extract"

    if args.context > 0:
        args.before_context = args.context
        args.after_context = args.context

    args.grep += flatten_sublists(args.grep_builtin)
    args.grep_not += flatten_sublists(args.grep_builtin_not)

    # Move key=regex args into separate variables
    args.grep_by_key, args.grep = make_regex_dict(args.grep)
    args.grep_not_by_key, args.grep_not = make_regex_dict(args.grep_not)

    # compile regexes to improve performance
    flags = re.IGNORECASE if args.ignore_case else 0
    try:
        args.grep = [re.compile(regex, flags) for regex in args.grep]
        args.grep_not = [re.compile(regex, flags) for regex in args.grep_not]
        args.grep_by_key = {
            key: re.compile(regex, flags) for key, regex in args.grep_by_key.items()
        }
        args.grep_not_by_key = {
            key: re.compile(regex, flags) for key, regex in args.grep_not_by_key.items()
        }
    except re.error as exc:
        print_err("Invalid regular expression:", exc)
        sys.exit(1)

    if args.ts_format:
        global datetime_converters
        global dt_conv_order
        # Try user-specified format first
        datetime_converters.insert(
            0, lambda s: dt.datetime.strptime(s, args.ts_format).astimezone()
        )
        dt_conv_order = list(range(len(datetime_converters)))

    if args.new:
        args.since = timedelta_from("0s")

    if args.since is not None:
        args.from_dt = dt.datetime.now().astimezone() - args.since
    if args.until is not None:
        args.to_dt = dt.datetime.now().astimezone() + args.until
    if args.duration is not None:
        if args.duration < dt.timedelta.resolution:
            print_err("Duration must not be zero. This would not select any data.")
            sys.exit(1)
        if args.from_dt is None:
            args.from_dt = dt.datetime.now(tz=dt.timezone.utc)
        if args.to_dt is None:
            args.to_dt = args.from_dt + args.duration
        else:
            args.to_dt = min(args.from_dt + args.duration, args.to_dt)
    if args.timespan is not None and args.timespan < dt.timedelta.resolution:
        print_err("Time span must not be zero. This would not select any data.")
        sys.exit(1)

    if args.plain or args.output_format in ["jsonl", "csv", "tsv", "psv", "json"]:
        args.output_quote = '"'
    elif args.unicode:
        args.output_quote = "\u201c"
    else:
        args.output_quote = INPUT_QUOTE

    args.output_width = None
    args.output_wrap = None

    if args.indent and not args.output_wrap:
        args.output_wrap = terminal_width
    if args.no_wrap:
        args.output_wrap = None
        args.output_width = terminal_width
    if args.output_sep:
        args.output_sep = args.output_sep.replace("\\n", "\n").replace("\\t", "\t")

    # Fake JSON output by wrapping JSONL items in a JSON array, separated by commas
    if args.output_format == "json":
        args.header = "["
        args.output_event_sep = ",\n"
        args.footer = "\n]"

    return args


def show_skipped_marker(skipped):
    colors = THEMES[args.theme]["skipped_marker"]
    print(
        colorize("\n  [...", colors["before"]),
        colorize(str(skipped), colors["number"]),
        colorize(
            "non-matching input line(s) not shown ...]\n",
            colors["after"],
        ),
        file=sys.stderr,
    )


def show_gap_marker(timedelta, width):
    colors = THEMES[args.theme]["gap_marker"]
    label = f"time gap: {timedelta}"
    separator = "_" * int((terminal_width - len(label) - 3) / 2)
    print(
        colorize(separator, colors["before"]),
        colorize(label, colors["label"]),
        colorize(
            "_" * int((terminal_width - 1 - len(label) - 1 - len(separator))),
            colors["after"],
        ),
        file=sys.stderr,
    )


def colored_levelchar(event):
    key, _ = get_log_level(event)
    return colored_mapchar(event, key)


def colored_mapchar(event, key):
    val = event.get(key, ".")
    color = None
    if val == ".":
        color = THEMES[args.theme]["quotes"] if args.color else None
    elif args.color:
        if key in MSG_KEYS:
            color = THEMES[args.theme]["message_key"]
        elif key in TS_KEYS:
            color = THEMES[args.theme]["timestamp_key"]
        elif key in LEVEL_KEYS:
            color = THEMES[args.theme]["levels"].get(val.lower(), "off")
    if args.color and color:
        return colorize(val[0], color)
    return val[0]


def logical_line_gen(file):
    logical_line = []
    for line in file:
        stripped = line.rstrip()
        if logical_line and logical_line[-1].endswith("\\"):
            # Continue the line if the previous line ended with a backslash
            logical_line[-1] = logical_line[-1][:-1]  # Remove the backslash
            logical_line.append(stripped)
        elif stripped and not line[0].isspace():
            # Start a new logical line if this line is non-empty and not indented
            if logical_line:
                yield "".join(logical_line)
                logical_line = []
            logical_line.append(stripped)
        else:
            # Continue the current logical line, with indentation removed
            # XXX: Maybe don't infer with tabs or multiple spaces?
            logical_line.append(stripped.lstrip())
    if logical_line:
        yield "".join(logical_line)


def extract_blocks(
    file_iterator,
    start_after=None,
    start_with=None,
    stop_before=None,
    stop_with=None,
    num_blocks=-1,
):
    """
    Extracts blocks of lines from a file iterator based on regex patterns.

    Args:
    file_iterator: An iterator yielding lines from a file
    start_after, start_with, stop_before, stop_with: Lists of regex patterns
    num_blocks: Number of blocks to extract (-1 for all blocks)

    Yields:
    Tuples of (block_lines, start_line_number, end_line_number)
    """

    def matches_any_pattern(line, patterns):
        return patterns and any(re.search(pattern, line) for pattern in patterns)

    blocks_found = 0
    started = not (start_after or start_with)
    current_block = []
    start_line_number = None

    for i, line in enumerate(file_iterator, start=1):
        if not started:
            if matches_any_pattern(line, start_after):
                started = True
                continue
            if matches_any_pattern(line, start_with):
                started = True
            else:
                continue

        if matches_any_pattern(line, stop_before):
            if current_block:
                yield current_block, start_line_number, i - 1
                blocks_found += 1
                if num_blocks != -1 and blocks_found == num_blocks:
                    return
            started = False
            current_block = []
            start_line_number = None
            continue

        current_block.append(line)
        if start_line_number is None:
            start_line_number = i

        if matches_any_pattern(line, stop_with):
            yield current_block, start_line_number, i
            blocks_found += 1
            if num_blocks != -1 and blocks_found == num_blocks:
                return
            started = False
            current_block = []
            start_line_number = None

    if current_block:
        yield current_block, start_line_number, i


def events_from_linebased(filenames, format, encoding="utf-8", skip=None):
    """Yields events from (multiple) line-based files, which may be compressed."""
    line_gen = logical_line_gen if args.logical_lines else (lambda f: f)
    if not filenames:
        filenames = ["-"]

    for filename in filenames:
        with file_opener(filename, encoding=encoding) as f:
            skip_lines(f, skip)

            for block, start_line, end_line in extract_blocks(
                line_gen(f),
                start_after=args.start_after,
                start_with=args.start_with,
                stop_before=args.stop_before,
                stop_with=args.stop_with,
                num_blocks=args.num_blocks,
            ):
                for i, line in enumerate(block, start=start_line):
                    event = parse_linebased(line, format)
                    events = apply_input_exec(event)
                    for event in events:
                        yield event, i


def get_sqlite_tablenames(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    return tables


def ensure_safe_tablename(tablename):
    """Ensure the table name contains only valid characters (e.g., letters, numbers, and underscores)"""
    if not re.match(r"^\w+$", tablename):
        raise ValueError("Invalid table name")


def events_from_sqlitefiles_generator(filenames, tablename):
    """Yields events from (multiple) sqlite files, which may be compressed."""
    if not filenames:
        filenames = ["-"]

    for filename in filenames:
        with file_opener(filename, sqlite_mode=True) as conn:
            cursor = conn.cursor()
            if not tablename:
                tablenames = get_sqlite_tablenames(cursor)[0]
                if len(tablenames) == 1:
                    tablename = tablenames[0]
                else:
                    raise ValueError(
                        "No table name specified and more than one table found:",
                        ", ".join(tablenames),
                    )
            if not tablename:
                raise ValueError("No table name specified and no tables found")

            ensure_safe_tablename(tablename)
            query = f"SELECT * FROM {tablename}"
            cursor.execute(query)

            # Get the column names
            column_names = [description[0] for description in cursor.description]

            # Fetch and yield each row as a dict
            for i, row in enumerate(cursor, start=1):
                yield dict(zip(column_names, row)), i


class MyTests(unittest.TestCase):
    def test_guess_datetime_military_ns(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00.123000000Z"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 123000, tzinfo=dt.timezone.utc),
        )

    def test_guess_datetime_military_ms(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00.123Z"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 123000, tzinfo=dt.timezone.utc),
        )

    def test_guess_datetime_military_s(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00Z"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 0, tzinfo=dt.timezone.utc),
        )

    def test_guess_datetime_no_tz_ns(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00.123000000"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 123000).astimezone(),
        )

    def test_guess_datetime_no_tz_ms(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00.123"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 123000).astimezone(),
        )

    def test_guess_datetime_no_tz(self):
        self.assertEqual(
            guess_datetime("2022-12-30T20:55:00"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 0).astimezone(),
        )

    def test_guess_datetime_only_date(self):
        self.assertEqual(
            guess_datetime("2022-12-30"),
            dt.datetime(2022, 12, 30, 0, 0, 0, 0).astimezone(),
        )

    def test_guess_datetime_only_year_month(self):
        self.assertEqual(
            guess_datetime("2022-12"),
            dt.datetime(2022, 12, 1, 0, 0, 0, 0).astimezone(),
        )

    def test_guess_datetime_offset(self):
        self.assertEqual(
            guess_datetime("2022-12-30T22:55:00+02:00"),
            dt.datetime(2022, 12, 30, 20, 55, 0, 0, tzinfo=dt.timezone.utc),
        )

    def test_timedelta_from_microseconds(self):
        self.assertEqual(
            timedelta_from("4us"),
            dt.timedelta(microseconds=4),
        )

    def test_timedelta_from_milliseconds(self):
        self.assertEqual(
            timedelta_from("4ms"),
            dt.timedelta(microseconds=4000),
        )

    def test_timedelta_from_seconds(self):
        self.assertEqual(
            timedelta_from("54s"),
            dt.timedelta(seconds=54),
        )

    def test_timedelta_from_minutes(self):
        self.assertEqual(
            timedelta_from("4m"),
            dt.timedelta(minutes=4),
        )

    def test_timedelta_from_hours(self):
        self.assertEqual(
            timedelta_from("4h"),
            dt.timedelta(hours=4),
        )

    def test_timedelta_from_days(self):
        self.assertEqual(
            timedelta_from("2d"),
            dt.timedelta(days=2),
        )

    def test_timedelta_from_weeks(self):
        self.assertEqual(
            timedelta_from("5w"),
            dt.timedelta(weeks=5),
        )

    def test_timedelta_from_floatseconds(self):
        self.assertEqual(
            timedelta_from("1.567s"),
            dt.timedelta(seconds=1, microseconds=567000),
        )

    def test_timedelta_from_no_unit(self):
        self.assertRaises(
            argparse.ArgumentTypeError,
            timedelta_from,
            "567",
        )

    def test_timedelta_from_no_negatives(self):
        self.assertRaises(
            argparse.ArgumentTypeError,
            timedelta_from,
            "-3s",
        )

    def test_builtin_regexes_compile(self):
        for name, regexes in BUILTIN_REGEXES.items():
            for regex in regexes:
                try:
                    re.compile(regex)
                except re.error as e:
                    self.fail(
                        f"Regex compilation for {name} failed with error: {e.msg}"
                    )

    # Logfmt parsing
    def test_parse_logfmt_basic(self):
        text = "key1=value1 key2=value2"
        expected = {"key1": "value1", "key2": "value2"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_spaces(self):
        text = 'key1="value with spaces" key2=value2'
        expected = {"key1": "value with spaces", "key2": "value2"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_escaped_quotes(self):
        text = 'key1="value with \\"escaped quotes\\"" key2=value2'
        expected = {"key1": 'value with "escaped quotes"', "key2": "value2"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_quotes_inside(self):
        text = 'key1=singlequote\'s key2=double"quot"es'
        expected = {"key1": "singlequote's", "key2": 'double"quot"es'}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_unicode(self):
        text = 'schlüssel=Schloß kauf="Äpfel aus Köln"'
        expected = {"schlüssel": "Schloß", "kauf": "Äpfel aus Köln"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_dots_in_key(self):
        text = "my.long.key=value1 key2=value2"
        expected = {"my.long.key": "value1", "key2": "value2"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_with_equal_in_val(self):
        text = "key=2+2=4 key2=test"
        expected = {"key": "2+2=4", "key2": "test"}
        self.assertEqual(parse_logfmt(text), expected)

    def test_parse_logfmt_empty_string(self):
        expected = {}
        text = ""
        self.assertEqual(parse_logfmt(text), expected)

    def test_escape1(self):
        text = 'a "string" with double quotes'
        expected = 'a \\"string\\" with double quotes'
        self.assertEqual(escape_doublequotes_quoted(text), expected)

    def test_escape2(self):
        text = "a 'string' with single quotes"
        expected = "a 'string' with single quotes"
        self.assertEqual(escape_doublequotes_quoted(text), expected)

    def test_escape3(self):
        text = "Escape seqs: \x00\t\n"
        expected = "Escape seqs: \\x00\\t\\n"
        self.assertEqual(escape_doublequotes_quoted(text), expected)

    def test_unescape(self):
        self.assertEqual(
            unescape(r"This is a \"test\" string"), 'This is a "test" string'
        )
        self.assertEqual(
            unescape(r"Escape sequences: \n \t"), "Escape sequences: \n \t"
        )
        self.assertEqual(unescape("значение со spaces"), "значение со spaces")
        self.assertEqual(unescape("\\x01"), "\x01")

    def test_extract_json_valid_json_object(self):
        self.assertEqual(
            extract_json('{"name": "John", "age": 30}'),
            '{"name": "John", "age": 30}',
        )

    def test_extract_json_valid_json_array(self):
        self.assertEqual(extract_json("[1, 2, 3, 4]"), "[1, 2, 3, 4]")

    def test_extract_json_nested_json(self):
        self.assertEqual(
            extract_json('{"person": {"name": "John", "age": 30}, "city": "New York"}'),
            '{"person": {"name": "John", "age": 30}, "city": "New York"}',
        )

    def test_extract_json_json_with_text_before(self):
        self.assertEqual(
            extract_json('Hello world {"name": "John", "age": 30}'),
            '{"name": "John", "age": 30}',
        )

    def test_extract_json_json_with_text_after(self):
        self.assertEqual(
            extract_json('{"name": "John", "age": 30} and more text'),
            '{"name": "John", "age": 30}',
        )

    def test_extract_json_invalid_json(self):
        with self.assertRaises(ValueError):
            extract_json('{"name": "John" "age": 30}')

    def test_extract_json_no_json(self):
        with self.assertRaises(ValueError):
            extract_json("Just a plain text without JSON")

    def test_extract_json_multiple_json_objects(self):
        self.assertEqual(
            extract_json('{"name": "John"} {"age": 30}'), '{"name": "John"}'
        )

    def test_extract_json_empty_string(self):
        with self.assertRaises(ValueError):
            extract_json("")

    def test_init(self):
        s = EStr("This is a test")
        self.assertEqual(s, "This is a test")

    def test_str(self):
        s = EStr("This is a test")
        self.assertEqual(str(s), "This is a test")

    def test_len(self):
        s = EStr("This is a test")
        self.assertEqual(len(s), 14)

    def test_getitem(self):
        s = EStr("This is a test")
        self.assertEqual(s[0], "T")
        self.assertEqual(s[1], "h")
        self.assertEqual(s[2], "i")
        self.assertEqual(s[3], "s")
        self.assertEqual(s[4], " ")
        self.assertEqual(s[5], "i")
        self.assertEqual(s[6], "s")
        self.assertEqual(s[7], " ")
        self.assertEqual(s[8], "a")

    def test_col(self):
        s = EStr("This is a test")
        self.assertEqual(s.col(0), "This")
        self.assertEqual(s.col(1), "is")
        self.assertEqual(s.col(2), "a")
        self.assertEqual(s.col(3), "test")
        self.assertEqual(s.col(4), None)

    def test_cols(self):
        s = EStr("This is  a test  with 7 columns")
        self.assertEqual(s.cols(), ["This", "is", "a", "test", "with", "7", "columns"])
        self.assertEqual(s.cols(0, 3), ["This", "test"])
        self.assertEqual(s.cols(0, -1, 2, 2), ["This", "columns", "a", "a"])
        self.assertEqual(s.cols("0,3"), "This test")
        self.assertEqual(s.cols("1"), "is")
        self.assertEqual(s.cols(1), "is")
        self.assertEqual(s.cols("14"), "")
        self.assertEqual(s.cols("1:3"), "is a")
        self.assertEqual(s.cols("-2,2,4:"), "7 a with 7 columns")
        self.assertEqual(s.cols("0,3", sep=" "), "This a")
        self.assertEqual(
            s.cols(-2, "0,4", "3:", 1, outsep="_"),
            ["7", "This_with", "test_with_7_columns", "is"],
        )

    def test_cols_sep(self):
        s = EStr("This|is a|test with|4 columns")
        self.assertEqual(s.cols("1:3", sep="|"), "is a test with")
        self.assertEqual(s.cols("-2,2,4:", sep="|", outsep=":"), "test with:test with")

    def test_cols_regexsep(self):
        s = EStr("This2334is7453a654test232with232regex")
        self.assertEqual(s.cols("1:5", sep=re.compile(r"\d+")), "is a test with")


def do_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(MyTests)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    return result


def flatten_object(json_data, separator="."):
    flattened = {}

    def _flatten(x, name=""):
        if isinstance(x, dict):
            for a in x:
                _flatten(x[a], name + a + separator)
        elif isinstance(x, list):
            i = 0
            for a in x:
                _flatten(a, name + str(i) + separator)
                i += 1
        else:
            flattened[name[:-1]] = x

    _flatten(json_data)
    return flattened


def sanitize_key(key):
    """Sanitize a JSON key to make it a valid Logfmt key"""
    return "".join(char if char.isalnum() else "_" for char in key)


def skip_lines(fileobj, n):
    if n is not None and n > 0:
        try:
            for _ in range(n):
                next(fileobj)
        except StopIteration:
            # End of file reached before skipping all lines
            pass


def events_from_jsonfiles_generator(filenames, encoding="utf-8", skip=None):
    if not filenames:
        filenames = ["-"]
    lineno = 0
    for filename in filenames:
        with file_opener(filename, encoding=encoding) as f:
            skip_lines(f, skip)
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError as e:
                if args.debug:
                    print_err("Invalid JSON syntax:", e)
            else:
                if isinstance(data, list):
                    for elem in data:
                        lineno += 1
                        events = apply_input_exec(flatten_object(elem))
                        for event in events:
                            yield event, lineno
                else:
                    lineno += 1
                    events = apply_input_exec(flatten_object(data))
                    for event in events:
                        yield event, lineno


import contextlib
import sys
import gzip
import zipfile
import io
import sqlite3


@contextlib.contextmanager
def file_opener(filename, encoding="utf-8", sqlite_mode=False):
    if filename in ["-", None]:
        yield sys.stdin
    elif filename.lower().endswith(".gz"):
        with gzip.open(filename, "rt", encoding=encoding) as f:
            yield f
    elif filename.lower().endswith(".zip"):
        if sqlite_mode:
            raise (NotImplementedError("Zipped SQLite databases are not supported."))
        with zipfile.ZipFile(filename, "r") as z:
            for name in z.namelist():
                with z.open(name) as f:
                    yield io.TextIOWrapper(f, encoding=encoding)
    else:
        if sqlite_mode:
            conn = sqlite3.connect(filename)
            yield conn
        else:
            with open(filename, "r", encoding=encoding) as f:
                yield f


def events_from_csvfiles_generator(
    filenames,
    delimiter=",",
    quoting=csv.QUOTE_MINIMAL,
    has_header=True,
    encoding="utf-8",
    skip=None,
    table=False,
):
    line_gen = logical_line_gen if args.logical_lines else (lambda f: f)
    if not filenames:
        filenames = ["-"]
    for filename in filenames:
        with file_opener(filename, encoding=encoding) as f:
            yield from process_csv(
                line_gen(f), delimiter, quoting, has_header, skip, table
            )


def process_csv(file_obj, delimiter, quoting, has_header, skip, table):
    if table:

        def read_whitespace_separated(file_obj):
            for line in file_obj:
                yield re.split(r"\s+", line.strip())

        reader = read_whitespace_separated(file_obj)
    else:
        reader = csv.reader(file_obj, delimiter=delimiter, quoting=quoting)

    skip_lines(reader, skip)

    if has_header:
        headers = next(reader)
        headers = [key for key in headers if key]
    else:
        headers = None
    for i, row in enumerate(reader):
        if headers:
            event = {
                sanitize_key(key): value for key, value in zip(headers, row) if key
            }
        else:
            event = {f"col{index}": value for index, value in enumerate(row)}
        for event in apply_input_exec(event):
            yield event, i + 1


def events_from_datafiles_generator(filenames, encoding="utf-8", skip=None):
    if not filenames:
        filenames = ["-"]
    for filename in filenames:
        with file_opener(filename, encoding=encoding) as f:
            skip_lines(f, skip)
            data = f.read()
            numlines = len(data.splitlines())
            events = apply_input_exec({"data": data})
            for event in events:
                yield event, numlines


def main():
    global args
    global is_first_visible_line
    interrupted = False
    stats = Stats([], [], [], 0, 0, "", "", "")
    try:
        args = parse_args()
        if args.selftest:
            if do_tests().wasSuccessful():
                sys.exit(0)
            else:
                sys.exit(1)
        if args.header:
            print_output(args.header)
        if args.output_format in ("csv", "tsv", "psv"):
            # Header
            args.writer.writerow(args.keys)
        show_context = (
            args.context or args.before_context or args.after_context
        ) and not args.stats_only
        before_context = collections.deque(maxlen=args.before_context)
        after_context_num = 0
        last_ts_datetime = None
        ts_delta = 0
        skipped = 0
        fuse_skipped = 0
        colored_mapline = []
        mapchars = 0
        formatted_time = ""
        len_formatted_time = 0
        fuse_maybe_last = None
        is_first_visible_line = True
        if args.input_format == "json":
            event_lineno_generator = events_from_jsonfiles_generator(
                args.files, encoding=args.input_encoding, skip=args.skip
            )
        elif args.input_format in ("csv", "tsv", "psv"):
            event_lineno_generator = events_from_csvfiles_generator(
                args.files,
                delimiter=args.input_delimiter,
                has_header=args.has_header,
                encoding=args.input_encoding,
                skip=args.skip,
                table=False,
            )
        elif args.input_format == "table":
            event_lineno_generator = events_from_csvfiles_generator(
                args.files,
                delimiter=args.input_delimiter,
                has_header=args.has_header,
                encoding=args.input_encoding,
                skip=args.skip,
                table=True,
            )
        elif args.input_format == "data":
            event_lineno_generator = events_from_datafiles_generator(
                args.files, encoding=args.input_encoding, skip=args.skip
            )
        elif args.input_format == "sqlite":
            event_lineno_generator = events_from_sqlitefiles_generator(
                args.files, tablename=args.input_tablename
            )
        else:
            event_lineno_generator = events_from_linebased(
                args.files,
                args.input_format,
                encoding=args.input_encoding,
                skip=args.skip,
            )
        for event, lineno in event_lineno_generator:
            stats.num_lines_seen = lineno

            if args.grep or args.grep_not:
                greppable = make_greppable(event)
                if (
                    args.grep_not
                    and any(regex.search(greppable) for regex in args.grep_not)
                ) or (
                    args.grep
                    and not any(regex.search(greppable) for regex in args.grep)
                ):
                    if after_context_num == 0:
                        if (
                            args.max_events
                            and stats.num_events_shown >= args.max_events
                        ):
                            raise StoppedEarly
                        if len(before_context) == args.before_context:
                            skipped += 1
                        before_context.append(event)
                        continue

            if args.add_ts:
                event["_klp_ts"] = now_rfc3339()
            if visible(event):
                # breakpoint()
                if args.fuse is not None or args.mark_gaps is not None:
                    ts_datetime = get_timestamp_datetime(event)
                    if ts_datetime is None:
                        # timestamp unknown: ignore event
                        if args.fuse is not None and fuse_maybe_last:
                            show(fuse_maybe_last)
                        continue
                    elif last_ts_datetime is None:
                        # first block ever: show
                        last_ts_datetime = ts_datetime
                    else:
                        ts_delta = ts_datetime - last_ts_datetime
                        last_ts_datetime = ts_datetime
                        if args.fuse is not None:
                            if ts_delta < args.fuse:
                                # old block, ignore for now, but save for later
                                # (will have to be printed if it was the last in block)
                                fuse_maybe_last = event
                                fuse_skipped += 1
                                continue
                            else:
                                # new block: show last event from last block first
                                if fuse_maybe_last:
                                    show(
                                        fuse_maybe_last,
                                        "fuse_last",
                                        lineno=1 + fuse_skipped + 1,
                                    )
                                    show_gap_marker(ts_delta, terminal_width)
                                    fuse_maybe_last = None
                        elif args.mark_gaps is not None:
                            if ts_delta > args.mark_gaps:
                                show_gap_marker(ts_delta, terminal_width)
                if show_context and skipped > 0 and args.output_format == "default":
                    show_skipped_marker(skipped)
                skipped = 0
                if args.max_events and stats.num_events_shown >= args.max_events:
                    raise StoppedEarly
                if args.add_ts_delta:
                    event, last_ts_datetime = add_ts_delta(event, last_ts_datetime)
                if (args.levelmap or args.keymap) and not args.stats_only:
                    mapchars += 1
                    if mapchars == 1:
                        ts = get_timestamp_str_or_none(event)
                        if ts:
                            formatted_time = format_datetime(ts)
                            # Cache value for more performance
                            len_formatted_time = len(formatted_time)
                            if args.color:
                                print_output(
                                    colorize(
                                        formatted_time,
                                        THEMES[args.theme]["timestamp_key"],
                                    ),
                                    end=" ",
                                )
                            else:
                                print_output(formatted_time, end=" ")
                    elif len_formatted_time + 1 + mapchars + 1 == terminal_width:
                        print_output("".join(colored_mapline))
                        colored_mapline = []
                        mapchars = 0
                    if args.levelmap:
                        colored_mapline.append(colored_levelchar(event))
                    else:
                        colored_mapline.append(colored_mapchar(event, args.keymap))
                    stats = update_stats(stats, event)
                    continue
                if not args.stats_only:
                    for before_event in before_context:
                        show(before_event, "before")
                        stats = update_stats(stats, before_event)
                    before_context.clear()
                    after_context_num = args.after_context
                    if args.fuse:
                        show(event, "fuse_first")
                        fuse_skipped = 0
                    elif args.context or args.before_context or args.after_context:
                        show(event, "match")
                    else:
                        show(event)
                stats = update_stats(stats, event)
            elif after_context_num > 0:
                if show_context and skipped > 0 and args.output_format == "default":
                    show_skipped_marker(skipped)
                skipped = 0
                after_context_num -= 1
                show(event, "after")
                stats = update_stats(stats, event)
            else:
                if len(before_context) == args.before_context:
                    skipped += 1
                before_context.append(event)
        skipped += len(before_context)
        if show_context and skipped > 0 and args.output_format == "default":
            show_skipped_marker(skipped)
        if colored_mapline:
            print_output("".join(colored_mapline))
        if fuse_maybe_last:
            show(fuse_maybe_last, "fuse_last", lineno=1 + fuse_skipped + 1)

    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
    except BrokenPipeError:
        # Ignore broken pipe errors (e.g. caused by piping our output to head)
        sys.stderr.close()  # Suppress further error messages
        pass
    except IOError as exc:
        if exc.errno == errno.EPIPE:
            pass
        else:
            raise
    except UnicodeEncodeError as e:
        print(
            f"Error: Unable to encode output using {args.output_encoding} encoding: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    except StoppedEarly:
        pass
    except KeyboardInterrupt:
        interrupted = True
        args.output_file.flush()
    finally:
        if args.output_file and args.output_file != sys.stdout:
            args.output_file.close()

    if args.cursor:
        args.conn.commit()
        args.conn.close()

    if args.footer is not None:
        print_output(args.footer)

    # Print stats even after CTRL-C or early stop
    if args.stats or args.stats_only:
        # New line only after ^C
        if interrupted:
            print_err()
        if args.output_format in ["jsonl", "json"]:
            show_stats_json(stats)
        else:
            show_stats(stats)


if __name__ == "__main__":
    main()
