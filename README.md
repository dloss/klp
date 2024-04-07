# klp

_Kool Logfmt Parser_

klp is a lightweight, command-line interface (CLI) tool  for analyzing and understanding structured logs in various formats.
Designed for software developers involved in debugging and troubleshooting.

Supports [logfmt](https://brandur.org/logfmt), [JSON Lines](https://jsonlines.org), [TSV](https://en.wikipedia.org/wiki/Tab-separated_values) and some other formats.

Single file Python script without dependencies apart from Python 3.7+ and its standard library. 

![](demo/basic.png)

## Key Features

- **Focus on the Essentials**: Instantly view the crucial fields: timestamp, log level, and message.
- **Selective Key Display**: Choose to include or exclude specific keys in your output.
- **Powerful Filtering**: Filter logs by log level or specific time ranges, e.g. to focus on new events. Employ Python expressions to specify complex filters.
- **Advanced Grep Capabilities**: Search whole lines or specific keys. Show context lines to see what happened right before or after an interesting event. Use built-in regexes for URLs, IPs, file paths or common errors.
- **Overview Stats**: Get a bird's eye view of your logs with a statistics page summarizing event count, keys, log levels, and time span. Or with a map of log levels.
- **Customizable Output**: Expand newlines, print each key on a separate line, or specify your own output templates, using Python [f-strings](https://realpython.com/python-f-strings/) or expressions
- **Enhanced Readability**: Enjoy colored and pretty-printed output for easier reading.
- **Supports JSON Lines and TSV** as alternative input/output formats (and some others)

klp is designed not for large-scale log analysis, but as a lightweight, efficient tool for developers. It's your companion for uncovering the mysteries in your logs, streamlining your development workflow, and accelerating troubleshooting.

## Installation

Copy `klp.py` to a folder on your PATH and make it executable:

```bash
$ install -m 755 klp.py ~/.local/bin/klp
```

Or just run it using `python3`, without any installation.

## Usage

klp can be used as a filter, reading from stdin:

```bash
$ tail -f log.txt | klp
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

* Timestamp keys: `timestamp`, `time`, `ts`, `t`, `at`
* Log level keys: `log_level`, `loglevel`, `level`, `lvl`, `severity`
* Message keys: `message`, `msg`

klp has special features to select events by timestamp or log level (see below).


### Default output

By default, klp prints every event that was recognized and shows both the key and the value of each field.
Colors are used for syntax-highlighting (use `--no-color` to turn this off or `--theme` to select different colors).

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
the timespan, the names of the keys and the log levels:

```bash
$ klp -S mylog.logfmt
Events shown: 8043 (100% of 8043 lines seen)
Time span shown: 2024-02-05T19:58:59.874Z to 2024-02-05T20:19:20.575Z (0:20:20.701000)
Keys seen: timestamp,log_level,source,target,thread_id,message
Log levels seen: DEBUG,TRACE,INFO (keys: log_level)
```

Use `--levelmap`/`-M` to print only the first character of the log level of each event.
The timestamp is for the first event shown in that line:

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

### Filter on log level

Use `--loglevel`/`-l` to restrict the output to specific log levels.
You can give a comma-separated list of levels.

```bash
$ cat mylog.txt | klp --loglevel warning,error,fatal
```

Exclude log levels with `--not-loglevel`/`-L`.
This is useful to suppress trace and debug output:

```bash
$ cat mylog.txt | klp -L trace,debug
```

### Filter on time

klp tries to parse timestamps automatically.
The following keys are treated as possibly holding timestamps: `timestamp`, `ts`, `time`, `at`.
You can specify your own key with `--ts-key KEY`.

klp includes a list of common time formats that will be tried for parsing.
Use `--ts-format` to specify your own format, using [Python strptime() format codes](https://docs.python.org/3/library/datetime.html#format-codes) (e.g. `%a %d %b %Y, %I:%M%p` to parse `Mon 31 Jan 2022, 11:59PM`).

There are multiple ways to specify the time range that you're interested in:

* absolute time: `--from ISODATETIME` and `--to ISODATETIME` 
* relative from now: `--since INTERVAL` and `--until INTERVAL` 
* timespan, computed from program start or first event shown: `--duration INTERVAL`, `--timespan INTERVAL`

Timespans can be specified with these units (for example: `--since 1w2h3.2s`):

- `w` = weeks
- `d` = days
- `h` = hours
- `m` = minutes
- `s` = seconds
- `ms` = milliseconds
- `us` = microseconds

Sometimes you want to skip old events and only want to see new events, e.g. when using `tail -f` or the `--follow` option of `kubectl`.
Use the `--new`/`-n` flag, which is equivalent to --since 0s`:

```bash
$ kubectl logs mypod --follow | klp -n
```

### Grep: searching with regexes, builtin regexes or Python expressions

Use `--grep`/`-g` to limit the processing to lines that match a given regular expression.
When this flag is given multiple times, any of those regexes matching 
will allow the line to be processed (logical OR).
If you need a logical AND, use an appropriate regex or pipe the output to another instance of klp.
To specify lines that should NOT be processed, use `--grep-not`/`-G`/`-v`.

Search is case-sensitive by default. 
Prepend `(?i)`to the regex for case-insensitive matches. 

By default, `--grep` searches on the whole line. 
To limit the search to a specific key, prepend that key and a tilde to the regex (`key~REGEX`).

klp has several builtin regexes to match URLs, email addresses, common errors, path names, FQDN's or IPv4 addresses.
Use `--grep-builtin`/`-r` to use them.

Like with with the original UNIX grep, klp can print context lines (`-B`, `-A`, `-C`).
Events before the matching line are visually marked with `/`, lines after with `\`.

### Complex filtering with Python expressions

Use `--where EXPR` to only process lines where the given Python expression is True.
All fields of the event are available by their key name.

```bash
$ cat httplog.txt | klp --where "len(message) > 10 and int(response[:3] > 499"
```

The whole event dict can be accessed as the underscore `_`.

By default, errors are ignored, because some keys might not be available in all lines. 
Use `--debug` to print exceptions.

This can be be combined with other filters, such as `--grep` and grep context lines.

### Limit the output

Use `--max-events`/`-m` to limit the output to the given number of events.
This is useful to avoid being flooded with lots and lots of output.

Use `--skip` to avoid parsing the first lines.

### Customize the output formatting

Experiment with `--indent`, `--expand`, `--output-sep` and `--each-key` to change the formatting of the output.

For more complex needs, you can use `--output-template` (with Python f-strings) or `--output-eval` which allows Python code, such as `{ts} {level.upper()} {'#'*len(msg)}`.
The following Python modules can be used in these expressions:
`base64`,
`collections`,
`datetime`,
`hashlib`,
`itertools`,
`json`,
`math`,
`pprint`,
`random`,
`re`,
`string`,
`textwrap`.

The following additional functions are available:

* `extract_first_json()`: return the first JSON object or array in a given string as a string
* `extract_first_email()`: return the first email address in a given string
* `extract_first_fqdn()`: return the first FQDN in a given string
* `extract_first_ipv4()`: return the first IPv4 address in a given string
* `extract_first_url()`: return the first URL in a given string
* `format_datetime()`: format given string according to ISO 8601 (with millisecond precision), guessing the datetime format  
* `guess_datetime()`: convert a string into a Python datetime object
* `pprint_json()`: pretty print JSON data

### Other input and output formats

Apart from logfmt, klp supports the following other data formats:

Input formats (`--input-format`/`-f`):
- `jsonl`: JSON Lines (shortcut: `-j`)
- `json`: JSON (only for complete files, not for streaming)
- `tsv`: Tab separated values (keys have to be set manually with `-k`)
- `psv`: Pipe separated values (keys have to be set manually with `-k`)
- `tap`: Output of `linkerd viz tap`
- `clf`: NCSA Common Log Format
- `combined`: Combined Log Format of Apache httpd
- `unix`: common format of Unix server logs (timestamp, hostname, service, optional pid, message)
- `line`: lines of text (trailing whitespace removed)

Output formats (`--output-format`/`-F`):
- `default`: logfmt
- `jsonl`: JSON Lines
- `tsv`: Tab separated values (keys have to be set manually with `-k`) 
- `psv`: Pipe separated values (keys have to be set manually with `-k`) 

The JSONL and TSV output formats are useful for further processing with tools like `jq` or `awk`.

### Synthetic fields

klp can add some additional fields to the event.
For performance reasons this is only done if you explitly list these keys using `--keys`/`-k`.

* `_ts`: timestamp showing when the event was shown by klp
* `_ts_delta`: time span between this event and the event before (hours:minutes:seconds.microseconds)
* `_line`: the complete line from the log file or string. This can be used to show timestamps for lines that aren't logfmt or JSONL.

## Complementary tools

These tools aren't specialized on log fiels, but useful to post-process or view klp`s output, particulary the JSONL or TSV formats:

- [jq](https://jqlang.github.io/jq/): a lightweight and flexible command-line JSON processor
- [jaq](https://github.com/01mf02/jaq): A jq clone focussed on correctness, speed, and simplicity
- [yq](https://github.com/mikefarah/yq): yq is a portable command-line YAML, JSON, XML, CSV, TOML and properties processor
- [Miller](https://github.com/johnkerl/miller): like awk, sed, cut, join, and sort for name-indexed data such as CSV, TSV, and tabular JSON 
- [qsv](https://github.com/jqnatividad/qsv): CSVs sliced, diced & analyzed
- [jc](https://github.com/kellyjonbrazil/jc): CLI tool and python library that converts the output of popular command-line tools, file-types, and common strings to JSON, YAML, or Dictionaries
- [jtbl](https://github.com/kellyjonbrazil/jtbl): CLI tool to convert JSON and JSON Lines to terminal, CSV, HTTP, and markdown tables
- [ov](https://github.com/noborus/ov): Feature-rich terminal-based text viewer. It is a so-called terminal pager.
- [csvlens](https://github.com/YS-L/csvlens): Command line csv viewer
- [Visidata](https://www.visidata.org): A terminal spreadsheet multitool for discovering and arranging data
- [Benthos](https://github.com/benthosdev/benthos.git): high performance and resilient stream processor, able to connect various sources and sinks in a range of brokering patterns and perform hydration, enrichments, transformations and filters on payloads

## Alternatives

If you don't like klp, maybe try one of these other tools:

#### Logfmt CLI/TUI

- [hutils](https://github.com/brandur/hutils): the original logfmt tools (Ruby)
- [lfq](https://github.com/mattcontinisio/lfq): command-line logfmt processor (Go). Quite similar to klp. Faster, but fewer features
- [angle-grinder](https://github.com/rcoh/angle-grinder): Slice and dice logs on the command line (Rust). Flexible query syntax
- [pq](https://github.com/iximiuz/pq): Parse and Query log files as time series
- [Kelpie](https://github.com/Yord/klp): small, fast, and magical command-line data processor similar to pxi, jq, mlr, and awk
- [lnav](https://github.com/tstack/lnav): very advanced log file viewer. Files-only (no streaming), lots of formats

#### JSON CLI/TUI

- [fblog](https://github.com/brocode/fblog): small command-line JSON Log viewer (Rust). Lua filters.
- [json-log-viewer](https://github.com/gistia/json-log-viewer): powerful terminal based viewer for JSON logs using ncurses (JavaScript). TUI
- [Toolong](https://github.com/Textualize/toolong): A terminal application to view, tail, merge, and search log files, plus JSONL (Python). TUI
- [sumoshell](https://github.com/SumoLogic/sumoshell): collection of utilities to improve analyzing log files (Go). Successor is angle-grinder.
- [l'oGGo](https://github.com/aurc/loggo): A powerful terminal app for structured log streaming (Go). TUI
- [hl](https://github.com/pamburus/hl): A log viewer that translates JSON logs into human-readable representation (Rust)
- [logdissect](https://github.com/dogoncouch/logdissect.git): CLI utility and Python module for analyzing log files and other data (Python). Multiple input formats

#### Unstructured logs CLI/TUI

- [tailspin](https://github.com/bensadeh/tailspin): A log file highlighter (Rust)
- [GoAccess](https://goaccess.io): real-time web log analyzer and interactive viewer that runs in a terminal in *nix systems or through your browser

#### Web UI

- [Klogg](https://github.com/variar/klogg): multi-platform GUI application that helps browse and search through long and complex log files
- [frontail](https://github.com/mthenw/frontail/): streaming logs to the browser
- [LogScreen](https://github.com/soorajshankar/logScreen): Loglines can be messy, read it better on a browser, `command | npx logscreen`
- [Logdy](https://logdy.dev): Web based real-time log viewer. Stream ANY content to a web UI with autogenerated filters. Parse any format with TypeScript

#### Large scale

- [OpenObserve](https://github.com/openobserve/openobserve): cloud-native observability platform built specifically for logs, metrics, traces, analytics, RUM, designed to work at petabyte scale
- [Graylog](https://github.com/Graylog2/graylog2-server): Free and open log management
- [Grafana Loki](https://grafana.com/docs/loki/latest/visualize/grafana/): horizontally-scalable, highly-available, multi-tenant log aggregation system
