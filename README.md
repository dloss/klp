# klp

Kool Logfmt Parser

Viewer for structured log files in key=value format (and some others).

Single file CLI tool without dependencies apart from Python 3.7+ and its standard library. 

## Features

- Select which keys to include or exclude from the output
- Quickly view the most important fields: timestamp, log level, message
- Restrict output to given log levels, time range or time delta (e.g. since 1h ago)
- Grep on the values of given keys, optionally with context lines. 
- Built-in regexes for URLs, email addresses, IPv4 addresses and common errors
- Filter using Python expressions, like "len(msg.split()) == 5 and int(port) > 1024"
- Statistics page to get a quick overview of the event count, keys, log levels and time span
- Colored output and pretty printing (can be turned off)
- Optional pretty printing with indentation, Unicode chars and tab/crlf expansion
- [JSON Lines](https://jsonlines.org) and tab-separated values (TSV) as alternative input and output formats
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
$ cat log.txt | klp
```

Or you can read from a file:

```bash
$ klp log.txt
```

Options can be given before or after the filename.

See `klp --help` for the list of available options.

### Basics

klp parses each line of the input file (or stdin stream) into an *event*.
If a line cannot be parsed, it is ignored silently.
An event can have several *fields* (key/value pairs).
The events in a file or stream don't have to have the same fields.

klp tries to automatically detect timestamps, log levels and log messages
by looking for the following keys:

* Timestamp keys: `timestamp`, `time`, `ts`
* Log level keys: `log_level`, `loglevel`, `level`, `lvl`, `severity`
* Message keys: `message`, `msg`

klp has special features to select events by timestamp or log level.


### Default output

By default, klp prints every event that was recognized and shows both the key and the value of each field.
Colors are used for syntax-highlighting.

### Common output format: timestamp, log level, message

Often the time stamp, log level and message are the most important fields.
Use `--common`/`-c` to print them, without showing the names of the keys (only the values):

```bash
$ klp -c mylog.txt
2023-01-17T07:55:48.233Z DEBUG preparing query s190578: select * from applications
2023-01-17T07:55:48.234Z DEBUG executing statement s190578 with parameters: []
2023-01-17T07:55:48.656Z DEBUG preparing query s190579: select * from oauthproviderconfig where id = 0
2023-01-17T07:55:48.657Z DEBUG executing statement s190579 with parameters: []
2023-01-17T07:55:48.662Z DEBUG preparing query s190580: select * from oauthproviderconfig where id = 0
2023-01-17T07:55:48.663Z DEBUG executing statement s190580 with parameters: []
```

### Get an overview of the log data

Use `--stats-only`/`-S` to get some basic statistics about number of events in the log file,
the timespan, the names of keys and the log levels:

```bash
$ klp -S mylog.logfmt
Events shown: 8043 (100% of 8043 lines seen)
Time span shown: 2024-02-05T19:58:59.874Z to 2024-02-05T20:19:20.575Z (0:20:20.701000)
Keys seen: timestamp,log_level,source,target,thread_id,message
Log levels seen: DEBUG,TRACE,INFO (keys: log_level)
```

Use `--levelmap`/`-M` to print only the first character of the log level of each event.
The timestamp is for the first event 

```bash
$ klp -M mylog.logfmt
2024-02-05T20:18:10.538Z TTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDIT
2024-02-05T20:18:30.546Z ITTTTTTTTTTTTTTTDDTTITITTTTTTTTTTTTTTITITTTTTTTTTTTTTTTTITITTTTTTTTTTTTTTTTITITT
2024-02-05T20:18:34.098Z TTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTT
2024-02-05T20:18:45.555Z TTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTITITTT
2024-02-05T20:19:02.666Z TTTTDTTTTTTTTTITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDT
2024-02-05T20:19:15.571Z TTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTT
```

### Select the keys to show

To select the fields yourself, use `--keys`/`-k` and a comma-separated list of keys to print:

```bash
$ klp -k timestamp,message mylog.txt
timestamp="2022-09-05T06:25:27.465Z" message="poll_read: waiting on response"
timestamp="2022-09-05T06:25:27.465Z" message="polled new request"
timestamp="2022-09-05T06:25:27.465Z" message="poll_write: waiting on request"
timestamp="2022-09-05T06:25:27.465Z" message="poll_flush: flushed"
timestamp="2022-09-05T06:25:27.466Z" message="poll_read: waiting on response"
```

Or specify the fields you want to exclude, using `--keys-not`/`-K`.
In this case, all the other fields will be printed.

Use `--plain`/`-p` to leave out the keys and only print the values:

```bash
$ cat mylog.txt | klp -k -p timestamp,message
2022-09-05T06:25:27.465Z poll_read: waiting on response
2022-09-05T06:25:27.465Z polled new request
2022-09-05T06:25:27.465Z poll_write: waiting on request
2022-09-05T06:25:27.465Z poll_flush: flushed
2022-09-05T06:25:27.466Z poll_read: waiting on response
```

#### Filter on log level

Use `--loglevel`/`-l` to filter on the `log_level` or `level` key.
You can give a comma-separated list of levels.

```bash
$ cat mylog.txt | klp --loglevel debug
```

Filter out log levels with `--not-loglevel`/`-L`.
This is useful to suppress trace and debug output:

```bash
$ cat mylog.txt | klp -L trace,debug
```

### Filter on time

There are multiple ways to specify the time range that you're interested in:

* absolute time: `--from` and `--to` 
* relative from now: `--since` and `--until` 
* timespan, computed from program start or first event shown: `--duration`, `--timespan`

#### Only show new events

Sometimes you want to skip old events and only want to see new events, e.g. when using `tail -f` or the `--follow` option of `kubectl`.
Use the `--new`/`-n` flag:

```bash
kubectl logs mypod --follow | klp -n
```

This is equivalent to `klp --since 0s`.
Other time spans can be specified.
Use `s` for seconds, `m` for minutes, `h` for hours and `d` for days.

### Limit the output

Use `--max-events`/`-m` to limit the output to the first N events.

### Output formats and formatting

Experiment with `--indent`, `--expand`, `--output-sep` and `--each-key` to change the formatting of the output.

For more complex needs, you can use `--output-template` (with Python f-strings) or `--output-eval` which allows Python code, such as. "{ts} {level.upper()} {'#'*len(msg)}"

## Alternatives

If you don't like klp, maybe try one of these other tools:

- [hutils](https://github.com/brandur/hutils): the original logfmt tools, written in Ruby
- [fblog](https://github.com/brocode/fblog): small command-line JSON Log view
- [json-log-viewer](https://github.com/gistia/json-log-viewer): powerful terminal based viewer for JSON logs using ncurses.
- [hl](https://github.com/pamburus/hl): A log viewer that translates JSON logs into human-readable representation.
- [lnav](https://lnav.org): very advanced log file viewer
- [Miller](https://github.com/johnkerl/miller): like awk, sed, cut, join, and sort for name-indexed data such as CSV, TSV, and tabular JSON 
- [jq](https://jqlang.github.io/jq/): a lightweight and flexible command-line JSON processor
- [Klogg](https://github.com/variar/klogg): multi-platform GUI application that helps browse and search through long and complex log files
- [Grafana Loki](https://grafana.com/docs/loki/latest/visualize/grafana/): horizontally-scalable, highly-available, multi-tenant log aggregation system
