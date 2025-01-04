#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 Dirk Loss
"""
klp: Kool Logfmt Parser

For logs in key=value format (and some others), show only the interesting parts
"""

# Standard library imports for functionality
import argparse
import contextlib
import csv
import dataclasses
import datetime as dt
import errno
import gzip
import inspect
import itertools
import io
import json
import multiprocessing
import os
import pprint
import re
import shlex
import shutil
import signal
import sqlite3
import sys
import textwrap
import unittest
import zipfile

from functools import partial

# Some modules to make available for filtering and templating
import base64
import collections
import datetime
import hashlib
import math
import random
import string

# Standard library typing imports
from typing import (
    Dict,
    Optional,
    Any,
    Tuple,
    List,
    Iterator,
    Union,
    TextIO,
    Callable,
    TypeVar,
)

# Type variable for generic types
T = TypeVar("T")  # Used for generic type hints if needed

__version__ = "0.73.1"

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
    r'(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+|-)'
)
RE_COMBINED = re.compile(
    r'(?P<host>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<size>\d+|-) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
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
            "critical": "bright_red",
            "emerg": "bright_red",
            "emergency": "bright_red",
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
    "function": [r"\b(([\w\.]+\([^)]*\)))"],
    "gitcommit": [r"\b(([0-9a-fA-F]{7,40}))\b"],
    "hexcolor": [r"((#[0-9A-Fa-f]{6}))\b"],
    "ipv4": [
        r"\b((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\b"
    ],
    "ipv6": [
        r"\b(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b"
    ],
    "isotime": [
        r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b)"
    ],
    "json": [r"((\{[^{}]*?\}))"],
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
        r'"(((?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|MERGE)\s+(?:(?!"|\().|\([^)]*\))*))"'
    ],
    "url": [
        r"\b(((?:[a-z][a-z0-9+.-]*):\/\/(?:(?:[^\s:@]+(?::[^\s:@]*)?@)?(?:[^\s:/?#]+)(?::\d+)?(?:\/[^\s?#]*)?(?:\?[^\s#]*)?(?:#[^\s]*)?)))\b"
    ],
    "uuid": [
        r"\b(([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}))\b"
    ],
    "version": [r"\b(([vV])\d+\.\d+(\.\d+)?(-[a-zA-Z0-9]+)?)\b"],
    "winpath": [r"((^|(?<=[^:\\]))(?:[A-Za-z]:|\\\\|\.|\.\.)?(?:\\[\w.()\- ]+)+\\?)"],
    "winregistry": [r"((HKEY_[A-Z_]+(?:\\[A-Za-z0-9_]+)+))"],
}


EPILOG = f"""
INTERVAL units: us=microseconds/ms=milliseconds/s=seconds/m=minutes/h=hours/d=days/w=weeks"
Highlighted keys: {','.join(TS_KEYS + MSG_KEYS + LEVEL_KEYS)}
"""

terminal_width = shutil.get_terminal_size((80, 24)).columns

_klp_global_num = 0
_klp_global_list = []
_klp_global_set = set({})
_klp_global_dict = {}


def build_globals_dict(modules: List[Any]) -> Dict[str, Any]:
    """
    Build a dictionary of modules and their exported functions for template evaluation.

    Creates a dictionary mapping names to module objects and functions for use in
    evaluating Python expressions in templates and filters.

    Args:
        modules: List of module objects to include in the globals dictionary

    Returns:
        Dict[str, Any]: Dictionary containing:
            - Module objects mapped to their names
            - Standard functions with their existing docstrings
            - Auto-generated regex extraction functions

    Side Effects:
        - Creates extraction functions for each builtin regex pattern
        - Preserves original docstrings of included functions
    """
    d = {}

    # Add the modules
    for module in modules:
        name = module.__name__
        d[name] = module

    # Add the standard functions - use their existing docstrings
    standard_funcs = [
        extract_json,
        extract_regex,
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

    for func in standard_funcs:
        d[func.__name__] = func

    # Add regex extraction functions
    for regex_name in BUILTIN_REGEXES:
        func = create_extraction_function(regex_name)
        d[func.__name__] = func

    return d


def print_output(*myargs: Any, **kwargs: Any) -> None:
    """
    Print output to the configured output file with specified arguments.

    Wrapper around the print function that directs output to args.output_file.
    All arguments are passed directly to print().

    Args:
        *myargs: Variable positional arguments to pass to print()
        **kwargs: Variable keyword arguments to pass to print()

    Side Effects:
        - Writes to file specified by args.output_file
        - Uses print() behavior for actual output

    Example:
        >>> print_output("test", end="\\n")  # Writes "test\\n" to args.output_file
    """
    print(*myargs, **kwargs, file=args.output_file)


def handle_error(
    message: str,
    e: Optional[Exception] = None,
    exitcode: int = 1,
    debug_eval: bool = False,
    debug_where: bool = False,
    **kwargs,
) -> None:
    """Handle errors according to error_handling setting.

    Args:
        message: Error description message
        e: Optional exception that was caught
        exitcode: Exit code to use when error_handling is "exit" (default: 1)
        debug_eval: Treat debug_eval like debug
        debug_where: Treat debug_where like debug
        **kwargs: Additional arguments passed to print_err

    Side Effects:
        - May print to stderr depending on error_handling setting
        - May exit program if error_handling is "exit"
    """
    error_text = f"{message}" if e is None else f"{message}: {e}"

    if args.error_handling == "ignore":
        if (
            args.debug
            or (debug_eval and args.debug_eval)
            or (debug_where and args.debug_where)
        ):
            print_err(error_text, **kwargs)
        return
    elif args.error_handling == "print":
        print_err(error_text, **kwargs)
    else:  # exit
        print_err(error_text, **kwargs)
        sys.exit(exitcode)


def get_default_process_count() -> int:
    """
    Calculate the default number of processes for parallel processing.

    Determines optimal process count based on CPU count, reserving one CPU
    for the main process to maintain system responsiveness.

    Returns:
        int: Number of processes to use:
            - CPU count minus 1 if multiple CPUs available
            - Minimum of 1 process
            - 1 if CPU count cannot be determined

    Notes:
        - Uses multiprocessing.cpu_count() when available
        - Handles NotImplementedError gracefully
        - Never returns less than 1
        - Used as default when parallel processing is enabled

    Example:
        On a 4-core system:
        >>> get_default_process_count()
        3
    """
    try:
        return max(multiprocessing.cpu_count() - 1, 1)
    except NotImplementedError:
        return 1


def extract_json(text: str) -> str:
    """
    Extract the first valid JSON object or array from a text string.

    The function searches for valid JSON structures within the text, attempting to extract
    complete JSON objects or arrays. It handles nested structures and ensures the extracted
    JSON is valid.

    Args:
        text (str): The string containing potential JSON content

    Returns:
        str: The first valid JSON object or array found in the text as a string

    Raises:
        ValueError: If no valid JSON object or array can be found in the input text

    Examples:
        >>> extract_json('foo { "key": "value" } bar')
        '{ "key": "value" }'
        >>> extract_json('[1, 2, {"a": "b"}]')
        '[1, 2, {"a": "b"}]'
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


def guess_datetime(timestamp: str) -> Optional[datetime.datetime]:
    """
    Attempt to convert a given timestamp string into a datetime object using various datetime converters.

    The function tries different datetime formats in order until it finds one that successfully parses
    the timestamp. When a successful format is found, it's moved to the front of the list to optimize
    future parsing of similar timestamps.

    Args:
        timestamp (str): The timestamp string to be converted

    Returns:
        Optional[datetime.datetime]: A datetime object if conversion is successful, None otherwise

    Side Effects:
        Updates the global dt_conv_order list to prioritize successful converters

    Examples:
        >>> guess_datetime("2024-03-16T14:30:00Z")
        datetime.datetime(2024, 3, 16, 14, 30, tzinfo=datetime.timezone.utc)
        >>> guess_datetime("invalid")
        None
    """
    global dt_conv_order
    datetime = None
    for i in dt_conv_order:
        converter = datetime_converters[i]
        try:
            datetime = converter(timestamp)
            # print("guess", i, timestamp, "as", datetime, datetime.tzname(), file=sys.stderr) # debug
            if datetime is None:
                continue
            else:
                break
        except (AttributeError, ValueError, TypeError):
            continue
    # Bring found converter to the front so that it's tried first next time
    if not dt_conv_order[0] == i:
        dt_conv_order.insert(0, dt_conv_order.pop(i))
    return datetime


def format_datetime(val):
    """
    Format a given datetime string into a standardized ISO 8601 format string with milliseconds precision.

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
        handle_error("Failed to format datetime", e)
    return val


def extract_regex(
    pattern: str, s: str, *groupargs: int
) -> Optional[Union[str, Tuple[str, ...]]]:
    r"""
    Extract substring(s) from text that match a specified regular expression pattern.

    Searches for the first match of a regex pattern in the input string and returns
    the specified capture groups.

    Args:
        pattern (str): The regular expression pattern to search for
        s (str): The string to search within
        *groupargs (int): Variable number of group indices to retrieve from the match

    Returns:
        Optional[Union[str, Tuple[str, ...]]]:
            - If one group requested: The matched group as string or None
            - If multiple groups: Tuple of matched groups or None
            - Returns None if pattern doesn't match

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


def create_extraction_function(regex_name: str) -> Callable[[str], Optional[str]]:
    """
    Create a function that extracts text matching a built-in regex pattern.

    Factory function that generates extraction functions for built-in regex patterns.
    The generated functions are named extract_{regex_name} and include proper docstrings.

    Args:
        regex_name: Name of the built-in regex pattern to use

    Returns:
        Callable[[str], Optional[str]]: Function that:
            - Takes a string argument
            - Returns first match of the pattern or None
            - Has descriptive name and docstring

    Example:
        >>> extract_email = create_extraction_function("email")
        >>> extract_email("Contact us at test@example.com")
        'test@example.com'
    """

    def extraction_function(s):
        """Extract the first match of a built-in regex pattern from a string.

        Args:
            s (str): String to search in

        Returns:
            str or None: First match of the pattern, or None if no match found
        """
        if regex_name in BUILTIN_REGEXES:
            pattern = BUILTIN_REGEXES[regex_name][0]
            match = re.search(pattern, s)
            if match:
                return match.group()
        return None

    doc = {
        "email": "email address",
        "err": "error value",
        "fqdn": "fully qualified domain name (FQDN)",
        "function": "function calls",
        "gitcommit": "git commit hash",
        "hexcolor": "hex color code",
        "ipv4": "IPv4 address",
        "ipv6": "IPv6 address",
        "isotime": "ISO 8601 datetime string",
        "json": "JSON string",
        "jwt": "JSON Web Token (JWT)",
        "mac": "MAC address",
        "md5": "MD5 hash",
        "path": "Unix file path",
        "oauth": "OAuth token",
        "sha1": "SHA-1 hash",
        "sha256": "SHA-256 hash",
        "sql": "SQL query",
        "url": "URL",
        "uuid": "UUID",
        "version": "software version identifier",
        "winregistry": "Windows registry key",
    }

    extraction_function.__name__ = f"extract_{regex_name}"
    pattern = doc.get(regex_name, regex_name)
    extraction_function.__doc__ = f"""Return the first {pattern} in a given string."""
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


def parse_chunk(chunk, input_format):
    return [parse_linebased(line, input_format) for line in chunk]


def init_worker():
    # Let the main process handle CTRL-C
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def parallel_process(
    file_paths: List[str], args: argparse.Namespace
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """
    Process multiple files in parallel using a process pool.

    Implements parallel processing of log files using Python's multiprocessing.
    Handles file chunking, worker initialization, and signal handling for
    graceful interruption.

    Args:
        file_paths: List of paths to files to process
        args: Command line arguments namespace containing:
            - parallel: Number of processes to use (or None for auto)
            - input_format: Format of input files
            - input_encoding: File encoding to use

    Yields:
        Tuple[Dict[str, Any], int]: Each tuple contains:
            - Parsed event dictionary
            - Line number in current file

    Side Effects:
        - Creates a process pool
        - Sets up signal handlers in worker processes
        - Chunks files for efficient parallel processing

    Notes:
        - Uses get_default_process_count() when args.parallel is None
        - Chunk size is fixed at 10000 lines for memory efficiency
        - Workers ignore SIGINT to allow main process to handle cleanup
    """

    def chunk_file(file_path):
        chunk_size = 10000
        with file_opener(file_path, encoding=args.input_encoding) as f:
            while True:
                chunk = list(itertools.islice(f, chunk_size))
                if not chunk:
                    break
                yield chunk

    parse_func = partial(parse_chunk, input_format=args.input_format)

    process_count = args.parallel or get_default_process_count()
    with multiprocessing.Pool(process_count, init_worker) as pool:
        for file_path in file_paths:
            chunks = chunk_file(file_path)
            start_line = 1
            for parsed_chunk in pool.imap(parse_func, chunks):
                for i, event in enumerate(parsed_chunk, start=start_line):
                    yield event, i
                start_line += len(parsed_chunk)


def parse_logfmt(text: str) -> Dict[str, str]:
    """
    Parse a logfmt-formatted string into a dictionary.

    Logfmt is a log format that produces logs as key-value pairs separated by spaces, where values
    can be either quoted or unquoted. This function extracts these pairs into a dictionary.

    Args:
        text (str): A logfmt-formatted string

    Returns:
        Dict[str, str]: A dictionary where keys are logfmt keys and values are their corresponding
                       unescaped values (quoted values are unescaped, unquoted values are kept as-is)

    Example:
        >>> parse_logfmt('key1="value 1" key2=simple')
        {'key1': 'value 1', 'key2': 'simple'}
    """
    return {
        key: (unescape(quoted_val) if quoted_val else unquoted_val)
        for key, quoted_val, unquoted_val in RE_LOGFMT.findall(text)
    }


def split_startswith(s: str, pattern: str) -> List[str]:
    """
    Split string into parts where each part starts with text matching a regex pattern.

    Splits a string into sections based on where matches of the pattern occur. The pattern
    matches are included at the start of each section except possibly the first one.

    Args:
        s (str): Input string that may contain newlines
        pattern (str): Regular expression pattern that should match the start of each part

    Returns:
        List[str]: List of string parts including:
            - Text before first match (if non-empty)
            - Parts starting with pattern match extending until next match
            - Final part from last match to end of string
        If pattern matches empty string or doesn't match, returns [s]

    Examples:
        >>> split_startswith("A.\\nB.\\nC.\\n", r"\\.\\n")
        ['A', '.\\nB', '.\\nC', '.\\n']
        >>> split_startswith("axbxcx", "x")
        ['a', 'xb', 'xc', 'x']
    """
    # Handle empty pattern or patterns that could match empty string
    if not pattern or re.match(pattern, ""):
        return [s]

    # If string is empty, return list with empty string
    if not s:
        return [""]

    # Find all starting positions of the pattern
    matches = list(re.finditer(pattern, s))

    # If no matches found, return the entire string
    if not matches:
        return [s]

    result = []

    # Add the part before first match only if it's non-empty
    if matches[0].start() > 0:
        result.append(s[: matches[0].start()])

    # Process each match
    for i, match in enumerate(matches):
        start = match.start()
        # If this is the last match, go to the end of string
        if i == len(matches) - 1:
            result.append(s[start:])
        else:
            # Otherwise, go until the start of the next match
            next_start = matches[i + 1].start()
            result.append(s[start:next_start])

    return result


def split_endswith(s, pattern):
    r"""
    Split a string into parts where each part ends with text matching the specified regex pattern.
    Uses greedy (non-overlapping) matching and preserves the pattern in the output.

    Args:
        s (str): Input string that may contain newlines
        pattern (str): Regular expression pattern that should match the end of each part

    Returns:
        List[str]: List of string parts, where each part ends with text matching the pattern.
                  If pattern matches empty string, returns [s].
                  If pattern doesn't match anywhere, returns [s].
                  Includes any remaining text after the last match.

    Examples:
        >>> split_endswith("A.\nB.\nC.\n", r"\.\n")
        ['A.\n', 'B.\n', 'C.\n']

        >>> split_endswith("A.\nB.\nC", r"\.\n")
        ['A.\n', 'B.\n', 'C']

        >>> split_endswith("aaaa", "aa")
        ['aa', 'aa']

        >>> split_endswith("x", "x")
        ['x']

        >>> split_endswith("axbxcx", "x")
        ['ax', 'bx', 'cx']

        >>> split_endswith("abc", ".*")
        ['abc']

        >>> split_endswith("", r"\.\n")
        ['']
    """
    # Handle empty pattern or patterns that could match empty string
    if not pattern or re.match(pattern, ""):
        return [s]

    # If string is empty, return list with empty string
    if not s:
        return [""]

    # Add end anchor to ensure we match at the end of each part
    regex = f".*?({pattern})"
    matches = list(re.finditer(regex, s, re.DOTALL))

    # If no matches found, return the entire string
    if not matches:
        return [s]

    # Build result from matches
    result = []
    last_end = 0

    for match in matches:
        result.append(s[last_end : match.end()])
        last_end = match.end()

    # Add remaining text if any
    if last_end < len(s):
        result.append(s[last_end:])

    return result


def parse_kv(
    text: str, sep: Optional[Union[str, re.Pattern]] = None, kvsep: str = "="
) -> Dict[str, str]:
    """
    Parse a string into key-value pairs using specified separators.

    Takes a string containing key-value pairs and splits it into a dictionary. Supports both string
    and regex pattern separators for flexible parsing of different formats.

    Args:
        text (str): The input string to parse
        sep (Optional[Union[str, re.Pattern]]): The separator between different key-value pairs.
            If None, any whitespace string is used as separator.
            Can be a string or compiled regular expression.
        kvsep (str): The separator between keys and values within each pair. Default is "="

    Returns:
        Dict[str, str]: A dictionary containing the parsed key-value pairs.
            Only includes pairs that contain the key-value separator.

    Examples:
        >>> parse_kv("key1=val1 key2=val2")
        {'key1': 'val1', 'key2': 'val2'}
        >>> parse_kv("key1:val1;key2:val2", sep=";", kvsep=":")
        {'key1': 'val1', 'key2': 'val2'}
        >>> parse_kv("key1=val1,key2=val2", sep=re.compile(r","))
        {'key1': 'val1', 'key2': 'val2'}
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


def parse_jsonl(line: str) -> Dict[str, str]:
    """
    Parse a line of JSONL (JSON Lines) format and extract string values.

    Processes a line containing a JSON object, focusing on top-level fields and
    converting all values to strings. Handles both pure JSONL and lines with
    additional text before/after the JSON object.

    Args:
        line (str): A string containing a JSON object, optionally with surrounding text

    Returns:
        Dict[str, str]: A dictionary where:
            - Keys are sanitized JSON keys
            - Values are string representations of the JSON values
            - Non-string values are converted to their string representation

    Side Effects:
        - Flattens nested objects with dot notation in keys

    Example:
        >>> parse_jsonl('{"name": "John", "age": 30, "nested": {"x": 1}}')
        {'name': 'John', 'age': '30', 'nested.x': '1'}
    """
    # Only handle top-level strings. Everything else is converted into a string
    result = {}
    try:
        # Ignore text before and after JSON object
        json_str = line[line.index("{") : line.rindex("}") + 1]
        json_data = json.loads(json_str)
    except (ValueError, json.decoder.JSONDecodeError) as exc:
        handle_error(f"{repr(line)}\nInvalid JSON syntax in the above line", exc)
        return result
    for key, val in flatten_object(json_data).items():
        if isinstance(val, str):
            result[sanitize_key(key)] = val
        else:
            result[sanitize_key(key)] = repr(val)
    return result


def parse_clf(line):
    """
    Parse a line in Common Log Format (CLF) and returns a dictionary of its components.

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


def parse_unix(line: str) -> Dict[str, str]:
    """
    Parse a line of log data in typical Unix server format into structured components.

    Parses log lines that contain timestamp, hostname, service name, and optional PID.
    Format example: "Mar 16 14:30:00 myhost myservice[1234]: Log message here"

    Args:
        line (str): A single line of log data in Unix format

    Returns:
        Dict[str, str]: A dictionary containing extracted components with keys:
            - 'timestamp': The timestamp string
            - 'hostname': The server hostname
            - 'service': The service name
            - 'message': The log message content
            - 'pid': The process ID (only if present in input)

    Example:
        >>> parse_unix("Mar 16 14:30:00 myhost myservice[1234]: Hello")
        {
            'timestamp': 'Mar 16 14:30:00',
            'hostname': 'myhost',
            'service': 'myservice',
            'pid': '1234',
            'message': 'Hello'
        }
    """
    match = RE_UNIX.match(line)
    if match:
        return {
            k: v for k, v in match.groupdict().items() if k != "pid" or v is not None
        }
    else:
        return {}


def _parse_log_line(line, ts_parts, has_level=False):
    """Generic parser for log lines with configurable timestamp parts and optional level.
    Returns empty dict for any lines that don't match the expected format exactly.

    Args:
        line (str): Input line to parse
        ts_parts (int): Number of parts that make up the timestamp (1-5)
        has_level (bool): Whether the line includes a level field after timestamp
    """
    line = line.strip()
    if not line:
        return {}

    # Calculate expected parts for a complete line
    total_parts = ts_parts + (2 if has_level else 1)  # +1 or +2 for level/message

    try:
        parts = line.split(maxsplit=total_parts - 1)
        if len(parts) != total_parts:
            return {}

        ts = " ".join(parts[:ts_parts])
        if has_level:
            return {
                "timestamp": ts,
                "level": parts[ts_parts],
                "message": parts[ts_parts + 1],
            }
        return {"timestamp": ts, "message": parts[ts_parts]}
    except Exception:
        return {}


def parse_ts1m(line):
    """Parse: <timestamp> <message>"""
    return _parse_log_line(line, ts_parts=1, has_level=False)


def parse_ts1lm(line):
    """Parse: <timestamp> <level> <message>"""
    return _parse_log_line(line, ts_parts=1, has_level=True)


def parse_ts2m(line):
    """Parse: <timestamp1> <timestamp2> <message>"""
    return _parse_log_line(line, ts_parts=2, has_level=False)


def parse_ts2lm(line):
    """Parse: <timestamp1> <timestamp2> <level> <message>"""
    return _parse_log_line(line, ts_parts=2, has_level=True)


def parse_ts3m(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <message>"""
    return _parse_log_line(line, ts_parts=3, has_level=False)


def parse_ts3lm(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <level> <message>"""
    return _parse_log_line(line, ts_parts=3, has_level=True)


def parse_ts4m(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <timestamp4> <message>"""
    return _parse_log_line(line, ts_parts=4, has_level=False)


def parse_ts4lm(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <timestamp4> <level> <message>"""
    return _parse_log_line(line, ts_parts=4, has_level=True)


def parse_ts5m(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <timestamp4> <timestamp5> <message>"""
    return _parse_log_line(line, ts_parts=5, has_level=False)


def parse_ts5lm(line):
    """Parse: <timestamp1> <timestamp2> <timestamp3> <timestamp4> <timestamp5> <level> <message>"""
    return _parse_log_line(line, ts_parts=5, has_level=True)


def parse_line(line: str) -> Dict[str, str]:
    """
    Parse a single line of text.

    Strips trailing whitespace characters and returns the cleaned line
    in a dictionary with the key 'line'.

    Args:
        line: The line of text to be parsed

    Returns:
        Dict[str, str]: A dictionary containing single key 'line' with
                       the cleaned line as its value

    Example:
        >>> parse_line("Hello World  \\n")
        {'line': 'Hello World'}
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
        split_startswith,
        split_endswith,
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
    """List all exported objects (modules and functions).

    Args:
        ignore_underscore (bool): Whether to ignore names starting with underscore

    Returns:
        list: List of exported objects
    """
    funcs = EXPORTED_GLOBALS.values()
    if ignore_underscore:
        funcs = [f for f in funcs if not getattr(f, "__name__", "").startswith("_")]
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


def timedelta_from(duration: str) -> datetime.timedelta:
    """
    Convert a duration string into a datetime.timedelta object.

    Parses duration strings with numerical values followed by time unit identifiers.
    Supports microseconds, milliseconds, seconds, minutes, hours, days, and weeks.

    Args:
        duration (str): Duration string (e.g., "5d", "3h30m", "2.5s", "500ms")

    Returns:
        datetime.timedelta: A timedelta object representing the duration

    Raises:
        argparse.ArgumentTypeError: If duration string is invalid or contains
                                  unsupported time units

    Supported units:
        - "us": microseconds
        - "ms": milliseconds
        - "s": seconds
        - "m": minutes
        - "h": hours
        - "d": days
        - "w": weeks

    Examples:
        >>> timedelta_from("5d")
        datetime.timedelta(days=5)
        >>> timedelta_from("3h30m")
        datetime.timedelta(hours=3, minutes=30)
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


def format_ts_delta(timedelta: Optional[datetime.timedelta]) -> str:
    """
    Format a timedelta object for consistent display with microsecond precision.

    Converts a timedelta to a string representation, ensuring consistent formatting
    with microseconds even when the timedelta has no fractional seconds.

    Args:
        timedelta: Time difference to format, or None

    Returns:
        str: Formatted string representation:
            - "unknown" if timedelta is None
            - String representation with .000000 if no microseconds
            - Standard string representation if microseconds present

    Examples:
        >>> format_ts_delta(datetime.timedelta(seconds=1))
        '1.000000'
        >>> format_ts_delta(datetime.timedelta(seconds=1, microseconds=500000))
        '1.500000'
        >>> format_ts_delta(None)
        'unknown'
    """
    if timedelta is None:
        return "unknown"
    # XXX: better heuristics
    s = str(timedelta)
    if "." not in s:
        s += ".000000"
    return s


def add_ts_delta(
    event: Dict[str, Any], last_ts_datetime: Optional[datetime.datetime]
) -> Tuple[Dict[str, Any], Optional[datetime.datetime]]:
    """
    Add timestamp delta to event and calculate the new last timestamp.

    Calculates the time difference between the current event's timestamp and the last seen timestamp,
    adds this delta to the event, and updates the last timestamp reference.

    Args:
        event (Dict[str, Any]): The event dictionary to process
        last_ts_datetime (Optional[datetime.datetime]): The timestamp of the last processed event

    Returns:
        Tuple[Dict[str, Any], Optional[datetime.datetime]]: A tuple containing:
            - The modified event with added delta
            - The updated last timestamp for use with next event

    Side Effects:
        Modifies the input event dictionary by adding a '_klp_timedelta' key

    Example:
        >>> event = {"timestamp": "2024-03-16T14:30:00Z", "message": "test"}
        >>> new_event, last_ts = add_ts_delta(event, None)
        >>> print(new_event['_klp_timedelta'])
        '2024-03-16 14:30:00.000000'
    """
    try:
        ts_datetime = get_timestamp_datetime(event)
        if ts_datetime is None:
            handle_error(f"No valid timestamp found in event {event}")
            return event, last_ts_datetime

        if last_ts_datetime is None:
            delta = ts_datetime
        else:
            try:
                delta = ts_datetime - last_ts_datetime
            except (TypeError, ValueError) as e:
                handle_error("Error calculating timestamp delta", e)
                return event, last_ts_datetime

        last_ts_datetime = ts_datetime

        # Add to start of event dict so delta is displayed first
        new_event = {"_klp_timedelta": format_ts_delta(delta)}
        new_event.update(event)
        return new_event, last_ts_datetime

    except Exception as e:
        handle_error("Error calculating timestamp delta", e)
        return event, last_ts_datetime


def datetime_from(text: str) -> datetime.datetime:
    """
    Parse date/time from command line argument format.

    Converts various textual date/time formats into datetime objects, supporting
    both absolute dates and relative references like 'today' or 'tomorrow'.

    Args:
        text: Date/time string, supporting formats:
            - ISO format timestamps
            - 'today', 'tomorrow', 'yesterday' (local midnight)
            - 'todayZ', 'tomorrowZ', 'yesterdayZ' (UTC midnight)
            - 'now' (current UTC time)

    Returns:
        datetime.datetime: Parsed datetime object with timezone information

    Raises:
        argparse.ArgumentTypeError: If text cannot be parsed as a valid timestamp

    Example:
        >>> datetime_from("today")  # Returns midnight today in local time
        >>> datetime_from("2024-03-16T14:30:00Z")  # Returns specific UTC time
    """
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
    # Classic Unix timestamp with weekday (Thu Sep 25 10:36:28 2003)
    lambda s: dt.datetime.strptime(s, "%a %b %d %H:%M:%S %Y").astimezone(),
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
    # Basic format YYYYMMDDTHHMMSS (20030925T104941)
    lambda s: (
        dt.datetime.strptime(s, "%Y%m%dT%H%M%S").astimezone()
        if 1900 <= int(s[:4]) <= 2100
        else None
    ),
    # Basic format YYYYMMDDHHMM (199709020900)
    lambda s: (
        dt.datetime.strptime(s, "%Y%m%d%H%M").astimezone()
        if 1900 <= int(s[:4]) <= 2100
        else None
    ),
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
    # Classic Unix timestamp format
    lambda s: dt.datetime.strptime(s, "%b %d %H:%M:%S %Y").astimezone(),
    # Short month with year
    lambda s: dt.datetime.strptime(s, "%b %d %Y").astimezone(),
    # 24-hour time only (assume current date)
    lambda s: dt.datetime.strptime(
        f"{dt.datetime.now().date()} {s}", "%Y-%m-%d %H:%M"
    ).astimezone(),
    # Year with month name and day
    lambda s: dt.datetime.strptime(s, "%Y %b %d").astimezone(),
    # DD-MM-YYYY format
    lambda s: dt.datetime.strptime(s, "%d-%m-%Y").astimezone(),
    # Month name, day with suffix, and year with apostrophe
    lambda s: dt.datetime.strptime(s.replace("'", ""), "%a, %B %d, %y").astimezone(),
    # Day with ordinal indicator and month name
    lambda s: dt.datetime.strptime(s.replace("rd of ", " "), "%d %B %Y").astimezone(),
    lambda s: dt.datetime.strptime(s.replace("st of ", " "), "%d %B %Y").astimezone(),
    lambda s: dt.datetime.strptime(s.replace("nd of ", " "), "%d %B %Y").astimezone(),
    lambda s: dt.datetime.strptime(s.replace("th of ", " "), "%d %B %Y").astimezone(),
    # HMS format with fractional seconds (10h36m28.5s)
    lambda s: dt.datetime.combine(
        dt.datetime.now().date(),
        dt.datetime.strptime(
            s.replace("h", ":").replace("m", ":").replace("s", ""), "%H:%M:%S.%f"
        ).time(),
    ).astimezone(),
    # AM/PM format (10am, 10pm)
    lambda s: dt.datetime.combine(
        dt.datetime.now().date(), dt.datetime.strptime(s, "%I%p").time()
    ).astimezone(),
]

dt_conv_order = list(range(len(datetime_converters)))


def now_rfc3339():
    return dt.datetime.now(tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")


def to_datetime(timestamp: Optional[str]) -> datetime.datetime:
    """
    Convert a timestamp string to a datetime object.

    Attempts to parse a timestamp using guess_datetime(). Raises an error if parsing
    fails or if timestamp is None.

    Args:
        timestamp: String representation of a timestamp, or None

    Returns:
        datetime.datetime: The parsed datetime object

    Raises:
        ValueError: If timestamp is None or cannot be parsed

    Example:
        >>> to_datetime("2024-03-16T14:30:00Z")
        datetime.datetime(2024, 3, 16, 14, 30, tzinfo=datetime.timezone.utc)
        >>> to_datetime(None)
        ValueError: No timestamp found.
    """
    if timestamp is None:
        raise ValueError("No timestamp found.")
    datetime = guess_datetime(timestamp)
    if datetime is None:
        raise ValueError(
            f"Could not parse timestamp '{timestamp}'. Use --ts-format to specify the format. See --help-time for syntax help"
        )
    return datetime


def get_timestamp_datetime(event: Dict[str, Any]) -> Optional[datetime.datetime]:
    """
    Extract and parse timestamp from an event dictionary into a datetime object.

    Attempts to find and parse a timestamp from common timestamp field names.
    If args.ts_key is specified, only that key is checked. Otherwise, tries
    several common timestamp keys in order.

    Args:
        event (Dict[str, Any]): Event dictionary that may contain timestamp fields

    Returns:
        Optional[datetime.datetime]: Parsed datetime object, or None if no valid timestamp found

    Side Effects:
        Uses global args.ts_key setting to determine which field to check first

    Example:
        >>> event = {"timestamp": "2024-03-16T14:30:00Z", "message": "test"}
        >>> dt = get_timestamp_datetime(event)
        >>> print(dt.isoformat())
        2024-03-16T14:30:00+00:00
    """
    if args.ts_key and args.ts_key in event:
        try:
            return to_datetime(event[args.ts_key])
        except ValueError:
            return None

    for key in ("timestamp", "ts", "time", "t", "at"):
        if key in event:
            try:
                return to_datetime(event[key])
            except ValueError:
                continue

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

    def __call__(self, *args, **kwargs):
        return self.cols(*args, **kwargs)

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

    def pprint_json(self, indent=2, sort_keys=True, ensure_ascii=False):
        return estr_or_none(pprint_json(self, indent, sort_keys, ensure_ascii))

    def sh(self, **kwargs):
        return estr_or_none(sh(str(self), **kwargs))

    def to_datetime(self):
        return to_datetime(str(self))

    def flatten_object(self, separator="."):
        return flatten_object(json.loads(str(self)), separator)

    def encode(self, encoding="utf-8", errors="strict"):
        return super().encode(encoding, errors)

    def decode(self, encoding="utf-8", errors="strict"):
        return estr_or_none(super().decode(encoding, errors))

    def endswith(self, suffix, start=None, end=None):
        return super().endswith(suffix, start, end)

    def startswith(self, prefix, start=None, end=None):
        return super().startswith(prefix, start, end)

    def translate(self, table):
        return estr_or_none(super().translate(table))

    def maketrans(self, x, y=None, z=None):
        return super().maketrans(x, y, z)

    def find(self, sub, start=None, end=None):
        return super().find(sub, start, end)

    def rfind(self, sub, start=None, end=None):
        return super().rfind(sub, start, end)

    def index(self, sub, start=None, end=None):
        return super().index(sub, start, end)

    def rindex(self, sub, start=None, end=None):
        return super().rindex(sub, start, end)

    def count(self, sub, start=None, end=None):
        return super().count(sub, start, end)

    def isalnum(self):
        return super().isalnum()

    def isalpha(self):
        return super().isalpha()

    def isdigit(self):
        return super().isdigit()

    def isspace(self):
        return super().isspace()

    def islower(self):
        return super().islower()

    def isupper(self):
        return super().isupper()

    def istitle(self):
        return super().istitle()

    def isprintable(self):
        return super().isprintable()

    def isidentifier(self):
        return super().isidentifier()

    def isnumeric(self):
        return super().isnumeric()

    def isdecimal(self):
        return super().isdecimal()

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
                    Can be a compiled regex. If empty string, splits after each character.
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
        ['This test']
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
        'is a test with'
        >>> t.cols("-2,2,4:", sep="|", outsep=":")  # Specify both column and output separators
        'test with:test with'
        """
        if isinstance(sep, re.Pattern):
            columns = re.split(sep, self)
        elif sep == "":
            columns = list(self)  # Split into individual characters
        else:
            columns = self.split(sep)

        columns = [EStr(c) for c in columns]
        if not args:
            return columns

        result = []
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

            # Join the results for this argument with outsep
            if arg_result:
                if len(args) > 1:
                    result.append(
                        estr_or_none(outsep.join([str(elem) for elem in arg_result]))
                    )
                else:
                    result.extend(arg_result)

        if len(args) == 1:
            return estr_or_none(outsep.join([str(elem) for elem in result]))
        return [EStr(elem) for elem in result]

    def extract_json(self):
        return estr_or_none(extract_json(self))

    def extract_regex(self, pattern, *groupargs):
        return estr_or_none(extract_regex(pattern, self, *groupargs))

    def format_datetime(self):
        return estr_or_none(format_datetime(self))

    def guess_datetime(self):
        return guess_datetime(self)

    def split_startswith(self, pattern):
        return split_startswith(self, pattern)

    def split_endswith(self, pattern):
        return split_endswith(self, pattern)

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

    def before(self, t: str) -> str:
        """Return the part of the string that comes before t.

        Args:
            t: Target substring to find

        Returns:
            Everything before the first occurrence of t, or empty string if not found.
            Returns empty string if t is longer than self.
            Returns empty string if source is empty.
            Returns source string if t is empty.

        Raises:
            TypeError: If t is None

        Examples:
            >>> EStr("name:alice").before(":")
            'name'
            >>> EStr("test").before("@")
            ''
            >>> EStr("a:b:c").before(":")
            'a'
        """
        if t is None:
            raise TypeError("Input cannot be None")

        if t == "":
            return self

        if self == "":
            return EStr("")

        if len(t) > len(self):
            return EStr("")

        try:
            index = self.index(t)
            return EStr(self[:index])
        except ValueError:
            return EStr("")

    def after(self, t: str) -> str:
        """Return the part of the string that comes after t.

        Args:
            t: Target substring to find

        Returns:
            Everything after the first occurrence of t, or empty string if not found.
            Returns empty string if t is longer than self.
            Returns empty string if source is empty.
            Returns source string if t is empty.

        Raises:
            TypeError: If t is None

        Examples:
            >>> EStr("name:alice").after(":")
            'alice'
            >>> EStr("test").after("@")
            ''
            >>> EStr("a:b:c").after(":")
            'b:c'
        """
        if t is None:
            raise TypeError("Input cannot be None")

        if t == "":
            return self
        if self == "":
            return EStr("")
        if len(t) > len(self):
            return EStr("")

        try:
            index = self.index(t)
            return self[index + len(t) :]
        except ValueError:
            return EStr("")

    def between(self, a: str, b: str) -> str:
        """Return the part of the string that lies between a and b.

        Args:
            a: Starting substring to find
            b: Ending substring to find after a

        Returns:
            Text between first occurrence of a and first occurrence of b after a.
            Returns empty string if either substring is not found.
            Returns empty string if a occurs after b.
            Returns empty string if source is empty.
            Returns source string if both a and b are empty.

        Raises:
            TypeError: If either a or b is None

        Examples:
            >>> EStr("name:alice:bob").between(":", ":")
            'alice'
            >>> EStr("<tag>value</tag>").between(">", "<")
            'value'
            >>> EStr("no delimiters").between("[", "]")
            ''
        """
        if a is None or b is None:
            raise TypeError("Input cannot be None")

        if a == "" and b == "":
            return self

        if self == "":
            return EStr("")

        after_a = self.after(a)
        if not after_a:
            return EStr("")

        return after_a.before(b)


def show(
    event: Dict[str, Any], context_type: str = "", lineno: Optional[int] = None
) -> None:
    """
    Display an event according to configured output format and styling.

    Central display function that handles all output formatting options including default,
    logfmt, JSON, CSV, and SQLite outputs. Applies color coding, wrapping, and other
    display options based on global configuration.

    Args:
        event: Dictionary containing event data to display
        context_type: Type of context marker to show ("before", "match", "after",
                     "fuse_first", "fuse_last", or ""). Default ""
        lineno: Optional line number to display with fused output

    Side Effects:
        - Writes output to args.output_file
        - Updates args.cursor for SQLite output

    Notes:
        Uses global args for configuration including:
        - output_format: Desired output format
        - output_template: Optional template for formatting
        - color: Whether to use ANSI colors
        - theme: Color theme to use
    """
    if not isinstance(event, dict):
        handle_error(f"Invalid event type: {type(event)}")
        return

    try:
        event = reorder(event)
        if not event:  # Skip empty events
            return

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
    except Exception as e:
        handle_error("Error showing event", e)


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
            handle_error(f"[Error evaluating {expr!r}", e, end=f". {event=}]\n")
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
    """Write event to SQLite with proper table name handling.

    Args:
        event (dict): Event dictionary to write
        cursor: SQLite cursor
    """
    if not cursor:
        return

    try:
        cols = []
        for key in args.keys:
            cols.append(escape_plain(event.get(key, "")))

        placeholders = ", ".join(["?" for _ in args.keys])
        # Use the table name from args
        query = f"INSERT INTO {args.output_tablename} VALUES ({placeholders})"
        cursor.execute(query, cols)
    except sqlite3.Error as e:
        print_err(f"SQLite error: {e}")
    except Exception as e:
        handle_error("Error writing to SQLite", e)


def show_default(
    event: Dict[str, Any], context_type: str = "", lineno: Optional[int] = None
) -> None:
    """
    Display an event using the default output format with color and formatting options.

    Main display function for human-readable output. Handles key coloring, line wrapping,
    indentation, and context markers for matched events.

    Args:
        event: Event dictionary to display
        context_type: Type of context marker to show (before/match/after/fuse_first/fuse_last)
        lineno: Optional line number for fused output

    Side Effects:
        - Writes to args.output_file
        - Applies ANSI color codes based on args.theme
        - May split output across multiple lines
        - Applies terminal width wrapping

    Configuration:
        Uses global args for:
        - color: Whether to use ANSI colors
        - theme: Color scheme to use
        - output_width: Maximum line width
        - output_wrap: Line wrapping settings
        - output_sep: Field separator
        - output_event_sep: Event separator
        - plain: Whether to show values only
        - expand: Whether to expand newlines/tabs

    Notes:
        - Handles key-specific coloring (timestamp, level, message)
        - Supports various quoting modes for values
        - Manages multi-line output formatting
        - Preserves ordering of keys
    """
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


def show_stats(stats: Stats) -> None:
    """
    Display statistics about the processed log data to stderr.

    Presents a formatted summary of log processing statistics including:
    - Number of events shown and percentage of total lines
    - Time span of shown events with events/second rate
    - Keys seen in the data
    - Log levels encountered and their associated keys

    Args:
        stats (Stats): A Stats dataclass object containing:
            - keys: List of all unique keys seen
            - loglevel_keys: List of keys used for log levels
            - loglevels: List of unique log levels seen
            - num_lines_seen: Total number of lines processed
            - num_events_shown: Number of events displayed
            - first_timestamp: First timestamp seen
            - last_timestamp: Last timestamp seen
            - timespan: Duration of processed logs

    Side Effects:
        Prints formatted statistics to stderr with optional ANSI colors

    Example:
        >>> stats = Stats(keys=['timestamp', 'message'],
                         loglevel_keys=['level'],
                         loglevels=['INFO', 'ERROR'],
                         num_lines_seen=100,
                         num_events_shown=50,
                         first_timestamp='2024-03-16T14:00:00Z',
                         last_timestamp='2024-03-16T15:00:00Z',
                         timespan='1:00:00')
        >>> show_stats(stats)
        Events shown: 50 (50% of 100 lines seen)
        Time span shown: 2024-03-16T14:00:00Z to 2024-03-16T15:00:00Z (1:00:00, 0.8 events/s)
        Keys seen: timestamp,message
        Log levels seen: INFO,ERROR (keys: level)
    """
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


def show_stats_json(stats: Stats, ensure_ascii: bool = False) -> None:
    """
    Output processing statistics in JSON format to stderr.

    Converts a Stats object to JSON and prints it to stderr with proper formatting.
    Useful for machine-readable output of processing statistics.

    Args:
        stats: Statistics object containing processing metrics
        ensure_ascii: Whether to escape non-ASCII characters in output.
                     Default False allows Unicode characters.

    Side Effects:
        - Writes to stderr
        - Converts dataclass to dictionary automatically
        - Uses 2-space indentation for output

    Notes:
        - Dumps the entire Stats object including:
            - keys: List of all unique keys seen
            - loglevel_keys: Keys used for logging levels
            - loglevels: Unique log levels encountered
            - num_lines_seen: Total lines processed
            - num_events_shown: Events displayed
            - first_timestamp: First event time seen
            - last_timestamp: Last event time seen
            - timespan: Total time covered

    Example:
        ```json
        {
          "keys": ["timestamp", "level", "message"],
          "loglevel_keys": ["level"],
          "loglevels": ["INFO", "ERROR"],
          "num_lines_seen": 100,
          "num_events_shown": 50,
          "first_timestamp": "2024-03-16T00:00:00Z",
          "last_timestamp": "2024-03-16T00:01:00Z",
          "timespan": "60.0"
        }
        ```
    """
    print_err(
        json.dumps(dataclasses.asdict(stats), indent=2, ensure_ascii=ensure_ascii)
    )


def update_stats(stats: Stats, event: Dict[str, Any]) -> Stats:
    """
    Update statistics object with data from a new event.

    Tracks various metrics about processed events including timestamps,
    log levels, and key usage. Only computes necessary statistics based
    on global configuration.

    Args:
        stats: Statistics object to update
        event: New event to process

    Returns:
        Stats: Updated statistics object (may be same object if modified in place)

    Side Effects:
        - May modify the input stats object
        - May update global args.to_dt based on timespan
        - May raise StoppedEarly if limits are reached

    Notes:
        Performance optimized - skips computation when stats aren't needed.
        Uses global args for configuration of:
            - stats: Whether to compute stats at all
            - stats_only: Whether only computing stats
            - max_events: Maximum events to process
            - timespan: Maximum time range to process
    """
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
    """Get timestamp string from event, handling missing/invalid keys."""
    if not isinstance(event, dict):
        return None

    if args.ts_key:
        return event.get(args.ts_key)

    for key in ("timestamp", "ts", "time", "at", "t"):
        value = event.get(key)
        if value is not None:
            return value


def get_log_level(event: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract the log level key and value from an event dictionary.

    Searches through common log level field names to find the first matching key
    and its corresponding value.

    Args:
        event: Event dictionary to search for log level

    Returns:
        Tuple[Optional[str], Optional[str]]: Tuple containing:
            - Name of the key containing log level (or None if not found)
            - Value of the log level (or None if not found)

    Notes:
        - Checks keys in order defined by LEVEL_KEYS global
        - Case sensitive key matching
        - Returns first matching key-value pair
        - Returns (None, None) if no log level found

    Example:
        >>> event = {"log_level": "INFO", "message": "test"}
        >>> get_log_level(event)
        ('log_level', 'INFO')
        >>> event = {"msg": "test"}
        >>> get_log_level(event)
        (None, None)
    """
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


def matches_python_expr(expr: str, event: Dict[str, Any]) -> bool:
    """
    Evaluate a Python expression against an event dictionary.

    Safely evaluates a Python expression with the event dictionary as local context,
    providing access to both the dictionary items directly and the full dictionary
    via underscore variables.

    Args:
        expr: Python expression string to evaluate
        event: Event dictionary providing context for evaluation

    Returns:
        bool: Result of expression evaluation, coerced to boolean

    Side Effects:
        - Uses EXPORTED_GLOBALS for evaluation context

    Notes:
        - Expression has access to event fields as variables
        - Full event available as '_' and '_klp_event'
        - Exceptions during evaluation return False
        - Uses restricted globals from EXPORTED_GLOBALS

    Example:
        >>> event = {"level": "ERROR", "count": 5}
        >>> matches_python_expr("level == 'ERROR' and count > 3", event)
        True
    """  #
    event = {k: v for k, v in event.items()}
    event_plus_underscore = event.copy()
    event_plus_underscore["_"] = event
    try:
        return eval(expr, EXPORTED_GLOBALS, event_plus_underscore)
    except Exception as e:
        handle_error(
            f"[Error matching {expr}",
            e,
            debug_where=True,
            end=f". {event=}]\n",
        )
        return False


def make_greppable(event: Dict[str, Any]) -> str:
    """
    Convert an event dictionary into a greppable string representation.

    Transforms event dictionary into a space-separated string of key="value" pairs
    suitable for pattern matching. This format enables consistent text-based
    searching across all event fields.

    Args:
        event: Event dictionary to convert

    Returns:
        str: Space-separated string of key="value" pairs

    Notes:
        - Always uses double quotes around values
        - Preserves original key order
        - Used for pattern matching in grep/grep-not operations
        - No escaping of quotes within values (used for pattern matching only)

    Example:
        >>> event = {"name": "test", "count": 42}
        >>> make_greppable(event)
        'name="test" count="42"'
    """
    return " ".join(f'{k}="{v}"' for k, v in event.items())


def visible(event: Dict[str, Any]) -> bool:
    """
    Determine if an event should be displayed based on all filtering criteria.

    Central filtering function that combines all filtering mechanisms including
    pattern matching, time ranges, log levels, and Python expressions.

    Args:
        event: Event dictionary to evaluate for visibility

    Returns:
        bool: True if event should be displayed, False otherwise

    Side Effects:
        - May raise StoppedEarly if time-based limits are exceeded

    Filter Application Order:
        1. Pattern exclusions (grep_not)
        2. Pattern matches (grep)
        3. Python expressions (where)
        4. Empty event check
        5. Key-specific pattern exclusions
        6. Key-specific pattern matches
        7. Time range checks
        8. Log level filters
        9. Key selection

    Notes:
        - Uses global args for all filtering criteria
        - Time range checks may raise StoppedEarly
        - Short-circuits on first failing criteria
        - Events with no selected keys are considered invisible
    """
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


def reorder(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Reorder and filter event keys based on command-line arguments.

    Reorders dictionary keys to match the order specified in command-line arguments
    and removes unwanted keys. The function creates a new dictionary with only the
    desired keys in the specified order.

    Args:
        event (Dict[str, Any]): Original event dictionary

    Returns:
        Dict[str, Any]: New dictionary with keys reordered and filtered according to:
            - args.keys: List of keys to include (in order)
            - args.keys_not: List of keys to exclude
            If args.keys is empty, includes all keys except those in args.keys_not

    Example:
        >>> event = {"c": 3, "a": 1, "b": 2}
        >>> # With args.keys = ["a", "b"] and args.keys_not = ["c"]
        >>> reorder(event)
        {'a': 1, 'b': 2}
    """
    return {
        key: event[key]
        for key in args.keys or event.keys()
        if key in event and key not in args.keys_not
    }


def input_exec(code: str, event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Execute Python code to transform event dict.

    Args:
        code: Python code to execute
        event: Input event dict

    Returns:
        List of transformed event dicts based on special output variables:
        - __/_klp_event_add: Modify single event
        - ___/_klp_events: Split into multiple events
        - No special vars: Return original event with underscore keys removed
    """

    SPECIAL_KEYS = {
        "_",
        "_klp_event",
        "__",
        "_klp_event_add",
        "___",
        "_klp_events",
        "_klp_global_num",
        "_klp_global_list",
        "_klp_global_set",
        "_klp_global_dict",
    }

    GLOBAL_VARS = [
        "_klp_global_num",
        "_klp_global_list",
        "_klp_global_set",
        "_klp_global_dict",
    ]

    def clean_event(event):
        return {
            k: v for k, v in event.items() if v is not None and k not in SPECIAL_KEYS
        }

    orig_event = event

    locals_dict = {
        **{key: EStr(val) for key, val in event.items()},
        "_": event,
        "_klp_event": event,
        **{var: globals()[var] for var in GLOBAL_VARS},
    }
    try:
        exec(code, EXPORTED_GLOBALS, locals_dict)
        event = locals_dict

        # Update globals
        for var in GLOBAL_VARS:
            if var in event:
                globals()[var] = event[var]

        if "___" in event:  # Multiple output events
            return [ev for ev in event["___"] if ev is not None]
        elif (
            "_klp_events" in event
        ):  # Multiple output events, more descriptive alternative
            return [ev for ev in event["_klp_events"] if ev is not None]
        elif "__" in event:  # One output event
            merged_event = {**event, **event["__"]}
            del merged_event["__"]
            return [clean_event(merged_event)]
        elif (
            "_klp_event_add" in event
        ):  # One output event, more descriptive alternative
            merged_event = {**event, **event["_klp_event_add"]}
            del merged_event["_klp_event_add"]
            return [clean_event(merged_event)]
        else:  # No special output
            return [clean_event(event)]
    except Exception as e:
        handle_error(
            f"[Error executing {args.input_exec!r}",
            e,
            debug_eval=True,
            end=f". {event=}]\n",
        )
        return [orig_event]


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
    """Print help information about available Python modules and functions."""
    exported_objects = list_exported_objects(ignore_underscore=True)

    # Default width used for module names
    name_width = 20

    # Separate and deduplicate modules and functions by name
    modules = {}
    functions = {}

    for obj in exported_objects:
        name = obj.__name__
        if inspect.ismodule(obj):
            modules[name] = obj
        elif inspect.isfunction(obj):
            functions[name] = obj

    # Print modules
    print("Modules:")
    for name, obj in sorted(modules.items()):
        doc = obj.__doc__.splitlines()[0] if obj.__doc__ else "No docstring"
        print(f" {name:<{name_width}}  {doc}")

    # Print functions
    print("\nFunctions:")
    for name, obj in sorted(functions.items()):
        sig = str(inspect.signature(obj))
        doc = inspect.getdoc(obj) or "No docstring"
        first_line = doc.splitlines()[0].strip()
        sig_text = f"{name}{sig}"

        # If signature is longer than default width, print it unaligned
        if len(sig_text) > name_width:
            print(f" {sig_text}  {first_line}")
        else:
            print(f" {sig_text:<{name_width}}  {first_line}")


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


def positive_int_or_zero(value):
    ivalue = int(value)
    if ivalue < 0:
        raise argparse.ArgumentTypeError(
            f"{value} is an invalid value. Use a positive integer or 0."
        )
    return ivalue


def validate_tablename(tablename):
    """Validate SQLite table name for argparse.

    Args:
        tablename (str): The table name to validate

    Returns:
        str: The validated table name

    Raises:
        argparse.ArgumentTypeError: If table name is invalid
    """
    try:
        if not tablename:
            raise ValueError("Table name cannot be empty")
        if not isinstance(tablename, str):
            raise ValueError(f"Table name must be string, got {type(tablename)}")
        if not re.match(r"^\w+$", tablename):
            raise ValueError(
                f"Table name '{tablename}' can only contain letters, numbers, and underscores"
            )
        return tablename
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))


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
    input.add_argument(
        "--max-block-lines",
        type=positive_int,
        default=10000,
        help="Maximum lines to buffer in a block before forcing yield (default: 10000)",
    )
    input.add_argument(
        "--ignore-mtime",
        action="store_true",
        help="process files in command-line order instead of by modification time",
    )
    input.add_argument(
        "--parallel",
        type=positive_int_or_zero,
        help="Enable parallel processing with specified number of processes. "
        "Use 0 to use the number of CPUs.",
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
        help=f"only process lines according to one of the built-in regexes {list(sorted(BUILTIN_REGEXES))}. Use 'key~REGEX' to limit to a specific key. Can be given multiple times. Any of them matching will allow the line to be processed",
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
        type=validate_tablename,
        help="SQLite table to write data to. Only letters, numbers, and underscores allowed. Default: data",
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
        "--errors",
        choices=["ignore", "print", "exit"],
        default="ignore",
        dest="error_handling",
        help="how to handle errors: ignore (default), print to stderr, or exit",
    )
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

    # Sort files by mtime unless ignored
    if args.files and not args.ignore_mtime:
        args.files = sort_files_by_mtime(args.files)

    args.color = (
        args.color
        or (not args.output_file and sys.stdout.isatty())
        and not (args.no_color or "NO_COLOR" in os.environ)
    )

    args.input_quoting = quoting_type(args.input_quoting)
    args.output_quoting = quoting_type(args.output_quoting)
    if args.output_file:
        try:
            args.output_file = open(args.output_file, "w")
        except FileNotFoundError:
            print("Could not open output file for writing:", repr(args.output_file))
            sys.exit(1)
    else:
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


def show_gap_marker(timedelta: Optional[datetime.timedelta], width: int) -> None:
    """
    Display a visual marker for time gaps between events.

    Creates a visual separator with timing information when there are significant
    time gaps between log events. Uses terminal width to format the separator.

    Args:
        timedelta: Time difference to display, or None to skip display
        width: Terminal width for formatting the marker

    Side Effects:
        - Prints formatted marker to stderr
        - Uses ANSI colors if enabled in args.theme
        - Respects terminal width for proper formatting

    Example Outputs:
        __________ time gap: 1:30:00 __________
        _____ time gap: 5 days, 2:15:30 ______
    """
    if timedelta is None:
        return

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
    if not val:
        return ""
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


def logical_line_gen(file: TextIO) -> Iterator[str]:
    """
    Generate logical lines from a text file, handling line continuations and indentation.

    Processes a text file to combine physical lines into logical lines based on:
    1. Backslash line continuations: lines ending with '\' continue to next line
    2. Indentation: indented lines are joined with previous non-indented line
    3. Line joining: removes the backslash and adds a single space between joined lines

    Args:
        file: A text file object that supports iteration over lines

    Yields:
        str: Complete logical lines with:
            - Continuation backslashes removed
            - Single space added between joined physical lines
            - Indentation stripped from continued lines
            - Original line preserved if no continuation or indentation

    Notes:
        - A logical line starts with a non-indented line
        - Indented lines are automatically considered continuations
        - Backslash at end of line explicitly marks continuation
        - Empty lines are not yielded
        - Preserves content but not original formatting

    Examples:
        Given input file content:
            first line\\
                continued line
            second line
            third line\\
                with indent\\
                more indent
        
        Yields:
            "first line continued line"
            "second line"
            "third line with indent more indent"
    """
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
            # Continue the current logical line, with indentation removed,
            # but add a single space character to avoid joining words
            # XXX: Maybe don't infer with tabs or multiple spaces?
            logical_line.append(" " + stripped.lstrip())
    if logical_line:
        yield "".join(logical_line)


def extract_blocks(
    file_iterator: Iterator[str],
    start_after: Optional[List[str]] = None,
    start_with: Optional[List[str]] = None,
    stop_before: Optional[List[str]] = None,
    stop_with: Optional[List[str]] = None,
    num_blocks: int = -1,
) -> Iterator[Tuple[List[str], int, int]]:
    """
    Extract blocks of lines from a file iterator based on regex patterns.

    This function processes an input stream and yields blocks of lines based on
    start and stop pattern matching. It supports streaming input and handles
    memory efficiently by limiting block sizes.

    Args:
        file_iterator: Iterator yielding lines from a file
        start_after: List of regex patterns to trigger block start after matching
        start_with: List of regex patterns to trigger block start with matching line
        stop_before: List of regex patterns to trigger block end before matching
        stop_with: List of regex patterns to trigger block end with matching line
        num_blocks: Number of blocks to extract (-1 for unlimited)

    Yields:
        Tuple[List[str], int, int]: Each tuple contains:
            - List of lines in the block
            - Starting line number of the block
            - Ending line number of the block

    Example:
        >>> with open('logfile.txt') as f:
        ...     for block, start, end in extract_blocks(f,
        ...             start_with=['START'],
        ...             stop_with=['END'],
        ...             num_blocks=1):
        ...         print(f"Lines {start}-{end}: {len(block)} lines")
    """

    # Maximum lines to accumulate before forcing a yield when no stop pattern seen
    MAX_BLOCK_LINES = 10000

    def matches_any_pattern(line, patterns):
        if not patterns:
            return False
        try:
            return any(re.search(pattern, line) for pattern in patterns)
        except (re.error, TypeError):
            return False

    if not any([start_after, start_with, stop_before, stop_with]):
        for i, line in enumerate(file_iterator, start=1):
            if not isinstance(line, str):
                continue
            yield [line], i, i
        return

    blocks_found = 0
    started = not (start_after or start_with)
    current_block = []
    start_line_number = None

    for i, line in enumerate(file_iterator, start=1):
        if not isinstance(line, str):
            continue

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

        # Force yield if block exceeds max size
        if len(current_block) >= MAX_BLOCK_LINES:
            yield current_block, start_line_number, i
            current_block = []
            start_line_number = None
            continue

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


def events_from_linebased(
    filenames: List[str],
    format: str,
    encoding: str = "utf-8",
    skip: Optional[int] = None,
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """
    Generate events from one or more line-based files, supporting various formats.

    A generator that reads and parses files line by line, handling different input
    formats and compression types. Supports file globbing and stdin.

    Args:
        filenames: List of files to process. Use ["-"] for stdin
        format: Format identifier (e.g., "logfmt", "jsonl", "clf")
        encoding: Character encoding of input files. Default UTF-8
        skip: Number of lines to skip at start of each file

    Yields:
        Tuple[Dict[str, Any], int]: Each tuple contains:
            - Parsed event dictionary
            - Line number in the current file

    Side Effects:
        - Uses global args for parsing configuration
        - Prints encoding error messages to stderr if they occur

    Raises:
        UnicodeDecodeError: If file cannot be decoded with specified encoding
    """
    line_gen = logical_line_gen if args.logical_lines else (lambda f: f)
    if not filenames:
        filenames = ["-"]

    for filename in filenames:
        try:
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
        except UnicodeDecodeError as e:
            print_err(
                f"Wrong encoding for '{filename}': {e}. Use --input-encoding to specify the correct encoding."
            )
            continue


def get_sqlite_tablenames(cursor):
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    return tables


def ensure_safe_tablename(tablename: str) -> None:
    """
    Validate SQLite table name to prevent SQL injection.

    Checks if a table name is safe to use in SQLite queries by verifying it
    contains only allowed characters and is properly formatted.

    Args:
        tablename: Name of table to validate

    Raises:
        ValueError: If table name is:
            - Empty
            - Not a string
            - Contains characters other than letters, numbers, underscore

    Notes:
        - Used before constructing SQLite queries
        - Validates using regex pattern '^\\w+$'
        - Case sensitive validation
        - No length limit enforced

    Example:
        >>> ensure_safe_tablename("valid_table_123")  # OK
        >>> ensure_safe_tablename("invalid-table")    # Raises ValueError
        >>> ensure_safe_tablename("")                 # Raises ValueError
    """
    if not tablename:
        raise ValueError("Table name cannot be empty")
    if not isinstance(tablename, str):
        raise ValueError(f"Table name must be string, got {type(tablename)}")
    if not re.match(r"^\w+$", tablename):
        raise ValueError(
            f"Invalid table name '{tablename}'. Use only letters, numbers, and underscores."
        )


def events_from_sqlitefiles_generator(
    filenames: List[str], tablename: Optional[str]
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """
    Generate events from SQLite database files.

    Reads records from SQLite databases, handling multiple files and table detection.
    Uses the file_opener context manager for handling regular and compressed files.

    Args:
        filenames: List of SQLite database files to process. Use ["-"] for stdin
        tablename: Name of table to read. If None, attempts to detect single table

    Yields:
        Tuple[Dict[str, Any], int]: Each tuple contains:
            - Dictionary mapping column names to values
            - Row number (1-based)

    Raises:
        ValueError: If no table name provided and multiple tables exist,
                   or if no tables found
        sqlite3.Error: For database access errors

    Notes:
        - Validates table names for SQL injection prevention
        - Uses file_opener context manager for file handling
        - Processes files sequentially, not in parallel
    """
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


class SelfTests(unittest.TestCase):
    # Tests that depend on the local system (e.g. local timezone)
    # and thus should be run on the live system
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


def do_tests():
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(SelfTests)
    runner = unittest.TextTestRunner()
    result = runner.run(suite)
    return result


def flatten_object(json_data: Any, separator: str = ".") -> Dict[str, Any]:
    """
    Flatten a nested JSON object or array into a single-level dictionary.

    Recursively traverses a JSON structure and creates a flat dictionary where nested
    keys are joined with the specified separator. Arrays are flattened using numeric indices.

    Args:
        json_data: Any JSON-serializable Python object (dict, list, etc.)
        separator: String to use between nested keys. Default "."

    Returns:
        Dict[str, Any]: Flattened dictionary where:
            - Nested dict keys are joined with separator
            - Array indices are included in keys
            - Only leaf values are included

    Example:
        >>> data = {"a": {"b": 1}, "c": [{"d": 2}, {"e": 3}]}
        >>> flatten_object(data)
        {'a.b': 1, 'c.0.d': 2, 'c.1.e': 3}
    """
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


def sanitize_key(key: str) -> str:
    """
    Convert a JSON/CSV key into a valid logfmt field name.

    Transforms potentially invalid key names into valid logfmt keys by replacing
    non-alphanumeric characters with underscores.

    Args:
        key: Input key name that may contain invalid characters

    Returns:
        str: Sanitized key name containing only alphanumeric characters and underscores

    Example:
        >>> sanitize_key("user.name@domain")
        'user_name_domain'
        >>> sanitize_key("valid_key_123")
        'valid_key_123'
    """
    return "".join(char if char.isalnum() else "_" for char in key)


def skip_lines(fileobj, n):
    if n is not None and n > 0:
        try:
            for _ in range(n):
                next(fileobj)
        except StopIteration:
            # End of file reached before skipping all lines
            pass


def events_from_jsonfiles_generator(
    filenames: List[str], encoding: str = "utf-8", skip: Optional[int] = None
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """
    Generate events from JSON files, handling both single objects and arrays.

    Processes JSON files that contain either single objects or arrays of objects.
    Flattens nested structures and supports compressed files through file_opener.

    Args:
        filenames: List of JSON files to process. Use ["-"] for stdin
        encoding: Character encoding of input files. Default UTF-8
        skip: Number of lines to skip before processing. Default None

    Yields:
        Tuple[Dict[str, Any], int]: Each tuple contains:
            - Flattened event dictionary
            - Line/object number (1-based)

    Side Effects:
        - Uses file_opener for file handling
        - Applies input_exec transformations to events

    Notes:
        - Flattens nested JSON structures with dot notation
        - Handles both single objects and arrays
        - For arrays, yields each element as separate event
        - For single objects, yields one event per file

    Example:
        Given file content:
            [{"a": {"b": 1}}, {"c": 2}]
        Yields:
            ({"a.b": 1}, 1)
            ({"c": 2}, 2)
    """
    if not filenames:
        filenames = ["-"]
    lineno = 0
    for filename in filenames:
        with file_opener(filename, encoding=encoding) as f:
            skip_lines(f, skip)
            try:
                data = json.load(f)
            except json.decoder.JSONDecodeError as e:
                handle_error("Invalid JSON syntax", e)
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


@contextlib.contextmanager
def file_opener(
    filename: str, encoding: str = "utf-8", sqlite_mode: bool = False
) -> Iterator[Union[TextIO, sqlite3.Connection]]:
    """
    Context manager for opening various types of input files.

    Provides unified handling of regular files, gzipped files, zip archives,
    and SQLite databases. Handles stdin via "-" filename.

    Args:
        filename: Path to file to open, use "-" for stdin
        encoding: Character encoding for text files. Default UTF-8
        sqlite_mode: Whether to open as SQLite database. Default False

    Yields:
        Union[TextIO, sqlite3.Connection]: Either:
            - File-like object for text input (regular, gzip, zip)
            - SQLite connection for database input

    Raises:
        NotImplementedError: If trying to open zipped SQLite database
        ValueError: If ZIP archive contains multiple files
        sqlite3.Error: For SQLite connection issues
        IOError: For file access issues

    Example:
        >>> with file_opener("data.txt.gz", encoding="utf-8") as f:
        ...     content = f.read()
    """
    if filename in ["-", None]:
        yield sys.stdin
    elif filename.lower().endswith(".gz"):
        with gzip.open(filename, "rt", encoding=encoding) as f:
            yield f
    elif filename.lower().endswith(".zip"):
        if sqlite_mode:
            raise NotImplementedError("Zipped SQLite databases are not supported.")
        with zipfile.ZipFile(filename, "r") as z:
            namelist = z.namelist()
            if len(namelist) != 1:
                raise ValueError("ZIP archives with multiple files are not supported")
            with z.open(namelist[0]) as f:
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


def process_csv(
    file_obj: Iterator[str],
    delimiter: str,
    quoting: int,
    has_header: bool,
    skip: Optional[int],
    table: bool,
) -> Iterator[Tuple[Dict[str, Any], int]]:
    """
    Process CSV/TSV/PSV data from a file object into event dictionaries.

    Handles both regular delimiter-separated files and whitespace-separated tables.
    Supports files with or without headers, and can skip initial lines.

    Args:
        file_obj: Iterator yielding lines from input file
        delimiter: Field separator character
        quoting: CSV quoting mode from csv module
        has_header: Whether first non-skipped line contains headers
        skip: Number of lines to skip before processing
        table: Whether to treat input as whitespace-separated table

    Yields:
        Tuple[Dict[str, Any], int]: Each tuple contains:
            - Event dictionary mapping column names to values
            - Line number in the input file

    Notes:
        - If has_header is False, generates column names as "col0", "col1", etc.
        - For table mode, splits on arbitrary whitespace instead of delimiter
    """
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


def get_file_mtime(file_path):
    """Get modification time of a file, handling special cases.

    Args:
        file_path (str): Path to the file

    Returns:
        float: Modification time as Unix timestamp, or float('inf') for stdin/non-existent
    """
    if file_path in ["-", None]:
        return float("inf")  # Put stdin last
    try:
        return os.path.getmtime(file_path)
    except (OSError, IOError):
        print(f"Warning: Could not get mtime for {file_path}", file=sys.stderr)
        return float("inf")  # Files with errors go last


def sort_files_by_mtime(filenames):
    """Sort files by modification time with older files first.

    Args:
        filenames (list): List of file paths

    Returns:
        list: Sorted list of file paths
    """
    return sorted(filenames, key=get_file_mtime)


def main():
    # Prevent Python from throwing BrokenPipeError at shutdown
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

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
            if args.parallel is not None:
                event_lineno_generator = parallel_process(args.files, args)
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

    except ValueError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
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
    except StoppedEarly:
        pass
    except KeyboardInterrupt:
        interrupted = True
        args.output_file.flush()

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
