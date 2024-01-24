# klp

Kool Logfmt Parser

Viewer for structured log files in key=value format (and some others).

Single file CLI tool without dependencies apart from Python 3.7+ and its standard library. 

## Features

- Select which keys to include or exclude from the output
- Quickly view the most important fields: timestamp, log level, message
- Restrict output to given log levels, time range or time delta (e.g. since 1h ago)
- Grep on the values of given keys, optionally with context lines. Built-in regexes for URLs, email addresses, IPv4 addresses and common errors
- Statistics page to get a quick overview of the event count, keys, log levels and time span
- Colored output and pretty printing (can be turned off)
- Optional pretty printing with indentation, Unicode chars and tab/crlf expansion
- JSON Lines and TSV as alternative input/output formats
- and more...

## Installation

Copy `klp.py` to a folder on your PATH and make it executable:

```bash
$ install -m 755 klp.py ~/.local/bin/klp
```

Or just run it using `python3`, without any installation.

## Usage

klp can be used as a filter, reading from stdin:

```bash
$ cat log.txt | klp <options>
```

Or you can read from a file:

```bash
$ klp <options> log.txt
```

See `klp --help` for the list of options.

## Examples

### Common output format

Only extract time stamp, log level and message:

```bash
$ kubectl logs db-api-server-5cdc577894-j8z92 | klp -c
2023-01-17T07:55:48.233Z DEBUG preparing query s190578: select * from applications
2023-01-17T07:55:48.234Z DEBUG executing statement s190578 with parameters: []
2023-01-17T07:55:48.656Z DEBUG preparing query s190579: select * from oauthproviderconfig where id = 0
2023-01-17T07:55:48.657Z DEBUG executing statement s190579 with parameters: []
2023-01-17T07:55:48.662Z DEBUG preparing query s190580: select * from oauthproviderconfig where id = 0
2023-01-17T07:55:48.663Z DEBUG executing statement s190580 with parameters: []
```

### Only show given fields

Use `--keys`/`-k` and a comma-separated list of keys to print:

```bash
$ kubectl logs db-api-server-5cdc577894-j8z92 | klp -k timestamp,message
timestamp="2022-09-05T06:25:27.465Z" message="poll_read: waiting on response"
timestamp="2022-09-05T06:25:27.465Z" message="polled new request"
timestamp="2022-09-05T06:25:27.465Z" message="poll_write: waiting on request"
timestamp="2022-09-05T06:25:27.465Z" message="poll_flush: flushed"
timestamp="2022-09-05T06:25:27.466Z" message="poll_read: waiting on response"
```

You can use `klp --common`/`-c` as a shorthand for `--keys ts,timestamp,msg,message`.

### Filter on log level

Use `--loglevel`/`-l` to filter on the `log_level` or `level` key.
You can give a comma-separated list of levels.

```bash
$ kubectl logs db-api-server-5cdc577894-j8z92 -f | klp -cp --loglevel debug
```

Filter out log levels with `--not-loglevel`/`-L`.
This is useful to suppress trace and debug output:

```bash
$ kubectl logs db-api-server-5cdc577894-j8z92 -f | klp -cp -L trace,debug
```

### Only show new output

Sometimes you want to skip old events and only want to see new events, e.g. when using the --follow option of kubectl:

```bash
kubectl logs db-api-server-5cdc577894-j8z92 -f | klp -n
```

This is equivalent to `klp --since 0s`.
Other time spans can be specified.
Use `s` for seconds, `m` for minutes, `h` for hours and `d` for days.

You can combine `--new`/`-n` with `--max-events`/`-m` to prevent scrolling.

## Alternatives

If you don't like klp, maybe try one of these other tools:

- [hutils](https://github.com/brandur/hutils): the original logfmt tools, written in Ruby
- [lnav](https://lnav.org): very advanced log file viewer
- [Miller](https://github.com/johnkerl/miller): like awk, sed, cut, join, and sort for name-indexed data such as CSV, TSV, and tabular JSON 
- [jq](https://jqlang.github.io/jq/): a lightweight and flexible command-line JSON processor
- [Klogg](https://github.com/variar/klogg): multi-platform GUI application that helps browse and search through long and complex log files
- [Grafana Loki](https://grafana.com/docs/loki/latest/visualize/grafana/): horizontally-scalable, highly-available, multi-tenant log aggregation system
