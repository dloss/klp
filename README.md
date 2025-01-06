# klp

_Kool Log Parser_

klp is a lightweight, command-line interface (CLI) tool for analyzing and understanding structured logs in various formats.
Designed for software developers involved in debugging and troubleshooting.

Supports [logfmt](https://brandur.org/logfmt), [JSON Lines](https://jsonlines.org),
[CSV](https://en.wikipedia.org/wiki/Comma-separated_values), [TSV](https://en.wikipedia.org/wiki/Tab-separated_values), [SQLite](https://sqlite.org) and many other formats.

Single file Python script without dependencies apart from Python 3.7+ and its standard library. 

![](demo/basic.png)

## Table of Contents

- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Basic Usage](#basic-usage)
- [Core Features](#core-features)
  - [Input Handling](#input-handling)
  - [Error Handling](#error-handling)
  - [Event Creation](#event-creation)
  - [Overview and Statistics](#overview-and-statistics)
  - [Time Management](#time-management)
  - [Search and Filter](#search-and-filter)
  - [Output Control](#output-control)
  - [Configuration File](#configuration-file)
- [Advanced Usage](#advanced-usage)
  - [Complex Filtering with Python Expressions](#complex-filtering-with-python-expressions)
  - [Advanced Input Transformations Using Python Code](#advanced-input-transformations-using-python-code)
  - [Custom Output Formatting using Python](#custom-output-formatting-using-python)
  - [Parsing Non-Line-Based Formats](#parsing-non-line-based-formats)
- [Additional Resources](#additional-resources)
  - [Complementary Tools](#complementary-tools)
  - [Alternative Tools](#alternative-tools)

## Key Features

- **Focus on Essentials**: 
Instantly highlight key fields: timestamp, log level, and message.
- **Advanced Time Analysis**:
Track time gaps in logs, fuse bursts of events, and filter by complex time ranges.
- **Smart Filtering**:
Filter by log level, time spans, or using Python expressions. 
- **Pattern Search**:
Grep in specific fields and show context lines. 
Use a wide range of built-in patterns to search or extract URLs, IPs, paths, email addresses, errors, and more. 
- **Visual Insights**:
Get statistics about the number of events and the occuring log levels, visually mark time gaps between events and see a succinct map of log level patterns.
- **Enhanced Readability**:
Color-coding, per-key display, expandable newlines and custom output templates using Python expressions. 
- **Format Conversion**:
Convert between common formats like logfmt, JSON, JSONL, CSV, TSV and SQLite.
- **Powerful Log Transformation**:  
Transform unstructured logs into structured data using Python code and convenient helper methods.
Create simple ad-hoc parsers for your own custom formats, add proper field names and save the result in any of the supported output formats.

## Getting Started

### Installation

Install using pip:

```bash
$ pip install klp-logviewer
```

Or just download `klp.py` and run it using `python3`, without any installation.

### Quick Start

Here are some basic examples to get you started with klp:

```bash
# View logs in logfmt format
$ klp mylog.logfmt

# Specify other input formats:
$ klp -f jsonl applog.jsonl
$ klp -f csv mydata.csv
$ klp -f line text.txt

# Only show specific keys
$ klp -k timestamp,level,message mylog.logfmt

# Don't print the keys, only the values
$ klp -p mylog.logfmt

# Filter logs by log level:
$ klp -l error,warning mylog.logfmt

# Get an overview of your log data:
$ klp -S mylog.logfmt

# View only new log entries (useful with streaming logs):
$ tail -f mylog.logfmt | klp -n
```

### Basic Usage

klp can be used as a filter, reading from stdin:

```bash
$ tail -f log.txt | klp
```

Or you can read from a file:

```bash
$ klp log.txt
```

klp can directly process compressed log files:

```bash
$ klp app.log.gz
$ klp logs.zip
```

Options can be given before or after the filename.
See `klp --help` for the list of available options.


#### Basic Filtering

**Filter by Log Level:**
Use `--loglevels`/`-l` to restrict the output to specific log levels:

```bash
$ cat mylog.txt | klp -l warning,error,fatal
```

Exclude log levels with `--not-loglevel`/`-L`:
```bash
$ cat mylog.txt | klp -L trace,debug
```

**Filter by Time:**
klp tries to parse timestamps automatically. 
The following keys are treated as possibly holding timestamps: `timestamp`, `ts`, `time`, `at`.

```bash
# Show events from the last hour
$ klp --since 1h app.log

# Show events from both a start and end time
$ klp --from "2024-02-05T20:18:10Z" --to "2024-02-05T20:19:20Z" app.log
```

**Filter by Regex:**

Use `--grep`/`-g` for simple text search with regular expressions:

```bash
# Search for specific text
$ klp -g "error" app.log

# Case-insensitive search
$ klp -g "error" -i app.log

# Search in specific fields
$ klp -g "message~error" app.log
```

## Core Features

### Input Handling

#### Supported input formats

klp supports a wide range of input formats:

- `logfmt`: Key-value pairs (**default**)
- `jsonl`: JSON Lines (shortcut: `-j`)
- `json`: JSON (only for complete files, not for streaming)
- `csv`: Comma-separated values 
- `tsv`: Tab separated values 
- `psv`: Pipe separated values 
- `line`: lines of text (trailing whitespace removed)
- `tsNm`: logs containing a timestamp (with N components) and a message. See below for examples. 
- `tsNlm`: logs containing a timestamp (with N components), a log level and a message
- `unix`: Common format of Unix server logs (timestamp, hostname, service, optional pid, message)
- `clf`: NCSA Common Log Format
- `combined`: Combined Log Format of Apache httpd
- `sqlite`: SQLite database (use `--input-tablename` if more than one table is present)
- `data`: Parse everything as one string 

Use the `--input-format` or `-f` option to specify the input format. For example:

```bash
$ klp -f jsonl input.log
```

The `tsNm` formats allows parsing logs that consist of a timestamp, and a message. 
`N` indicates how many whitespace-separated components the timestamp consists of.
Use `tsNlm` for logs that contain a log level between the timestamp and the message.
Here are some examples:

```bash
# Log format: <timestamp> <message>
# Example:    2024-02-05T20:18:10.538Z Connection established to database
$ klp -f ts1m server.log

# Log format: <date> <time> <level> <message>
# Example:    2024-02-05 20:18:10 INFO Starting background worker
$ klp -f ts2lm worker.log

# Log format: <date> <time> <timezone> <message>
# Example:    2024-02-05 20:18:10 UTC Processing batch job #1234
$ klp -f ts3m batch.log
```

Similar formats exist up to `ts5m`/`ts5lm` for logs with more timestamp components.
The timestamp parts are joined and parsed using klp's standard timestamp parsing logic.

More complicated formats can often be parsed using the `line` format and creating or transforming events using Python code (`--input-exec`).
See the [Advanced input transformations using Python code](#advanced-input-transformations-using-python-code) section below.
Alternatively, you can check out [jc](https://github.com/kellyjonbrazil/jc), a tool that converts numerous formats to JSON, which can be read by klp `-f json`.

#### Input Options

klp provides several options to control how input data is read and parsed:

- `--input-encoding`: Specify the text encoding of the input data (default: utf-8)
  ```bash
  # Read a file with Latin-1 encoding
  $ klp --input-encoding latin1 legacy.logfmt
  
  # Process Windows-1252 encoded logs
  $ klp -f line --input-encoding cp1252 windows.log
  ```

- `--no-header`: For CSV, TSV, or PSV formats, indicates that the file has no header row.
  This will auto-generate numbered column keys.
  ```bash
  # Process a headerless CSV file (columns will be named col0, col1, etc.)
  $ klp -f csv --no-header data.csv
  ```

- `--input-delimiter`: Specify the delimiter for CSV, TSV, or PSV formats
  ```bash
  # Process a file with semicolon-separated values
  $ klp -f csv --input-delimiter ";" european.csv
  
  # Read a custom-delimited file
  $ klp -f csv --input-delimiter ":" custom.log
  ```

- `--skip`: Avoid parsing the first N lines (e.g. to skip comments or old data).
  ```bash
  # Skip the first 5 lines of a CSV file
  $ klp -f csv --skip 5 data.csv
  ```

- `--logical-lines`: Handle log entries that span multiple physical lines by combining related lines into a single event. Two methods are supported:
 
  1. *Indentation Continuation*: Lines starting with whitespace are joined with a space between them (indentation removed)

  ```bash
  $ cat multi_indented.log
  Starting SQL query:
      SELECT * FROM users
      WHERE active = true
  Query completed

  $ klp -f line --logical-lines multi_indented.log
  line="Starting SQL query: SELECT * FROM users WHERE active = true"
  line="Query completed"
  ```
  2. *Backslash Continuation*: Lines ending with `\` are concatenated with the next line (backslash removed)

  ```bash
  $ cat multi_backslash.log
  Dec 16 10:15:30 shade app[123]: Starting a long process \
  with multiple arguments and lots of long configuration o\
  ptions
  Dec 16 10:15:31 shade app[123]: Process completed

  $ klp -f unix --logical-lines multi_backslash.log
  timestamp="Dec 16 10:15:30" hostname=shade service=app pid=123 message="Starting a long process with multiple arguments and lots of long configuration options"
  timestamp="Dec 16 10:15:31" hostname=shade service=app pid=123 message="Process completed"
  ```

  The `--logical-lines` option can be combined with any line-based input format and works with streaming input.
  It processes the lines before they are parsed according to the input format, so it works transparently with all klp's features.

#### Error Handling

Control how klp handles errors with the `--errors` option:

- `ignore` (default): Silently continue processing when errors occur. With `--debug`, errors will still be printed.
- `print`: Print error messages to stderr but continue processing
- `exit`: Print error messages to stderr and exit with status code 1

```bash
# Print parsing errors but continue processing
$ klp --errors print malformed.log

# Stop processing at first error
$ klp --errors exit app.log

# Process as much as possible, ignoring errors (default)
$ klp --errors ignore mixed.log

# Show errors even in ignore mode
$ klp --errors ignore --debug mixed.log
```

### Event Creation

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


### Overview and Statistics

#### Stats View
Use `--stats-only`/`-S` to get some basic statistics about number of events in the log file,
the timespan, the names of the keys and the log levels:

```bash
$ klp -S mylog.logfmt
Events shown: 8043 (100% of 8043 lines seen)
Time span shown: 2024-02-05T19:58:59.874Z to 2024-02-05T20:19:20.575Z (0:20:20.701000)
Keys seen: timestamp,log_level,source,target,thread_id,message
Log levels seen: DEBUG,TRACE,INFO (keys: log_level)
```

Or use `--stats`/`-s` to print those stats (to stderr), in addition to regular output.

#### Level Map
Use `--levelmap`/`-M` to print only the first character of the log level of each event.
The timestamp is for the first event shown in that line:

```bash
$ klp -M mylog.logfmt
2024-02-05T20:18:10.538Z TTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDITITTTTTTTTTTTTTTTDTTTDIT
2024-02-05T20:18:30.546Z ITTTTTTTTTTTTTTTDDTTITITTTTTTTTTTTTTTITITTTTTTTTTTTTTTTTITITTTTTTTTTTTTTTTTITITT
```

#### Key Map
Visualize patterns for any key:

```bash
$ klp --keymap status_code app.log
```

### Time Management

#### Time Filtering

klp tries to parse timestamps automatically.
The following keys are treated as possibly holding timestamps: `timestamp`, `ts`, `time`, `at`.
You can specify your own key with `--ts-key KEY`.

klp includes a list of common time formats that will be tried for parsing.
Use `--ts-format` to specify your own format, using [Python strptime() format codes](https://docs.python.org/3/library/datetime.html#format-codes) (e.g. `%a %d %b %Y, %I:%M%p` to parse `Mon 31 Jan 2022, 11:59PM`).
A short reference of the format codes can be printed with `klp --help-time`.

There are multiple ways to specify the time range that you're interested in:

* absolute time: `--from ISODATETIME` and `--to ISODATETIME` 
* relative from now: `--since INTERVAL` and `--until INTERVAL` 
* timespan, computed from program start: `--duration INTERVAL`
* timespan, computed from first event shown: , `--timespan INTERVAL`

Timespans can be specified with these units (for example: `--since 1w2h3.2s`):

- `w` = weeks
- `d` = days
- `h` = hours
- `m` = minutes
- `s` = seconds
- `ms` = milliseconds
- `us` = microseconds

#### Timezone Control
By default, klp preserves timestamps as they appear in the logs.
Use the following options to control how timestamps are displayed:

* `--localtime`/`-z`: Convert timestamps to your local timezone
* `--utc`/`-Z`: Convert timestamps to UTC

```bash
# Show timestamps in local timezone
$ klp --localtime -c mylog.logfmt
2015-03-26T06:27:38.000+01:00 debug Started observing beach

# Show timestamps in UTC
$ klp --utc -c mylog.logfmt
2015-03-26T05:27:38.000Z debug Started observing beach
```

Note that timezone conversion can slightly impact performance when processing large log files.
Only use these options when timezone conversion is specifically needed.

These options cannot be used together - choose either local time or UTC.
They work with all input formats and can be combined with other timestamp-related features like `--since`, `--until`, and `--timespan`.


#### Time Gaps
Use `--mark-gaps` to visually separate events that are far apart in time:

```bash
$ klp prometheus.logfmt -c --mark-gaps 1h
2024-02-05T11:00:02.081Z info Deleting obsolete block
_______________________________ time gap: 1:59:59.984000 ________________________________
2024-02-05T13:00:02.065Z info write block
2024-02-05T13:00:02.075Z info Head GC completed
2024-02-05T13:00:02.076Z info Creating checkpoint
2024-02-05T13:00:02.235Z info WAL checkpoint complete
_______________________________ time gap: 1:59:59.666000 ________________________________
2024-02-05T15:00:01.901Z info write block
2024-02-05T15:00:01.905Z info Head GC completed
_______________________________ time gap: 1:59:59.984000 ________________________________
2024-02-05T17:00:01.889Z info write block
2024-02-05T17:00:01.893Z info Head GC completed
```

#### Event Condensing
The `--fuse` option allows you to condense events that occur close together in time.

```bash
$ klp -c --fuse 1h prometheus.logfmt
1 2024-02-05T15:00:01.901Z info write block
3 2024-02-05T15:00:01.905Z info Head GC completed
_______________________________ time gap: 1:59:59.984000 ________________________________
1 2024-02-05T17:00:01.889Z info write block
9 2024-02-05T17:00:02.111Z info Deleting obsolete block
_______________________________ time gap: 1:59:59.782000 ________________________________
1 2024-02-05T19:00:01.893Z info write block
3 2024-02-05T19:00:01.897Z info Head GC completed
```

This shows only the first and last events for each group of events that occur within 1 hour of each other.
From the event number in the first column you can see how many events were left out.

### Search and Filter

#### Grep Capabilities
Use `--grep`/`-g` to limit the processing to lines that match a given regular expression.
When this flag is given multiple times, any of those regexes matching 
will allow the line to be processed (logical OR).

```bash
# Search with multiple patterns (OR)
$ klp -g "error" -g "warning" app.log

# Search in specific fields
$ klp -g "message~error" app.log
```

To specify lines that should NOT be processed, use `--grep-not`/`-G`/`-v`.

Search is case-sensitive by default. 
Use `--ignore-case`/`-i` for case-insensitive matches.

#### Context Lines
Like with the original UNIX grep, klp can print context lines:
- `-B N`: Show N lines before match
- `-A N`: Show N lines after match
- `-C N`: Show N lines before and after match

Events before the matching line are visually marked with `/`, lines after with `\`.

#### Built-in Patterns
klp has several builtin regexes to match URLs, email addresses, common errors, path names, FQDN's or IPv4 addresses.
Use `--grep-builtin`/`-r` to use them for matching lines or `--grep-builtin-not`/`-R` for ignoring them.

Use `--extract`/`-x` to output only the matched portions:

```bash
# Extract email addresses
$ klp -f line -x email mail.log

# Extract all URLs from JSONL logs
$ klp -f jsonl --extract url app.jsonl

# Extract both IPs and error messages
$ klp -x ipv4 -x err server.logfmt
```

Use `klp -x ?` to list all available extraction patterns.
They are also documented as `extract_*()` functions in `klp --help-python` screen.


### Select Blocks of Lines
You can define start and stop conditions to process specific blocks of logs:

- `--start-after REGEX`: Start processing after a line matching REGEX
- `--start-with REGEX`: Start processing when a line matches REGEX
- `--stop-with REGEX`: Stop processing after a line matches REGEX
- `--stop-before REGEX`: Stop processing when a line matches REGEX

```bash
$ klp --start-after "Session started" --stop-before "Session ended" app.log
$ klp --start-with "[Uu]ser \w+ logged in" --stop-with "[Uu]ser \w+ logged out" app.log
```

Use `--num-blocks` to limit the number of start/stop blocks processed.


### Output Control

#### Default Output

By default, klp prints every event that was recognized and shows both the key and the value of each field.
Colors are used for syntax-highlighting (use `--no-color` or the `NOCOLOR` environment variable to turn this off or `--theme` to select different colors).


#### Key Selection
To select specific fields, use `--keys`/`-k` and a comma-separated list of keys:

```bash
$ klp -k timestamp,message mylog.txt
timestamp="2022-09-05T06:25:27.465Z" message="poll_read: waiting on response"
```

Or specify fields to exclude using `--keys-not`/`-K`.

Use `--plain`/`-p` to leave out the keys and only print the values:

```bash
$ cat mylog.txt | klp -k -p timestamp,message
2022-09-05T06:25:27.465Z poll_read: waiting on response
```

#### Common Output Format

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

#### Synthetic Fields
klp can add some additional, synthetic fields to the event.
For performance reasons this is only done if you explicitly list these keys using `--keys`/`-k`.

* `_klp_timedelta`: time span between this event and the event before (hours:minutes:seconds.microseconds)
* `_klp_ts`: timestamp showing when the event was shown by klp

#### Output Formats
klp supports multiple output formats:

- `default`: Colored and formatted logfmt
- `logfmt`: Plain logfmt
- `jsonl`: JSON Lines (shortcut: `-J`)
- `json`: JSON
- `csv`: Comma separated values
- `tsv`: Tab separated values 
- `psv`: Pipe separated values
- `sqlite`: SQLite database (use `--output-tablename` to set table name. Default: `data`)
- `extract`: Only output the grep matches

Select an output format with `--output-format` or `-F`:

```bash
$ klp -F jsonl app.log > output.jsonl
$ klp -F sqlite -o app.db app.log
```

#### Custom Formatting
Customize your output with:

- `--header`: Add text before the first event
- `--footer`: Add text after the last event
- `--output-sep`: Specify the separator between fields
- `--output-event-sep`: Specify the separator between events (default: newline)
- `--output-delimiter`: CSV/TSV/PSV output delimiter
- `--output-quoting`: CSV/TSV/PSV output quoting (`minimal`,`all`,`nonnumeric`,`none`)
- `--indent`, `--no-indent`: Control indentation
- `--expand`: Expand newlines
- `--no-wrap`: Disable line wrapping
- `--each-key`: Print each key on a separate line

For advanced formatting, see [Custom Output Formatting using Python](#custom-output-formatting-using-python).

#### Output File Control
Use `--output-file`/`-o` to direct output to a file instead of stdout.
This can be used to convert the events to a different file format:

```bash
# Write formatted output to a file
$ klp app.log -o processed.log

# Convert to JSON for later processing
$ klp app.log -F json -o events.json

# Write events to file but show stats on screen
$ klp app.log -s -F jsonl -o events.jsonl
```

Note: Using `--output-file` disables color output by default, unless explicitly requested with `--color`.

### Configuration File

klp can be configured using an INI-style configuration file. The configuration allows setting default options and defining aliases for commonly used argument combinations.

#### File Locations

The configuration file is searched for in these locations (in order):
1. `$XDG_CONFIG_HOME/klp/config.ini` (usually `~/.config/klp/config.ini`)
2. `~/.klprc` (legacy compatibility)

On Windows:
1. `%APPDATA%\klp\config.ini`
2. `%USERPROFILE%\.klprc`

Use `klp --show-config` to see the current configuration and search locations.

#### File Format

The configuration file uses INI format with two sections:

```ini
[defaults]
# Default values for command line options
input-format = logfmt
input-encoding = utf-8
errors = ignore

[aliases]
# Define shortcuts for commonly used argument combinations.
# Aliases can reference other aliases with -a.

# Input format shortcuts
fmt_spring = -f line -I 'ts,level,thread,cls,msg=line.split("|",4)'
fmt_java = -f line -I 'ts,level,thread,msg=line.cols("0","1","2","3:")'

# Output format shortcuts
style_brief = -k timestamp,level,message -p
style_full = -k timestamp,level,source,thread,message

# Combined format (references other aliases)
spring_brief = -a fmt_spring -a style_brief
```

Use aliases with the `-a/--alias` option, which can be specified multiple times:

```bash
# Use a single alias
$ klp -a fmt_spring app.log

# Combine multiple aliases
$ klp -a fmt_spring -a style_brief app.log

# Mix with other options
$ klp -a spring_brief --mark-gaps 1h app.log
```

## Advanced Usage

### Complex Filtering with Python Expressions

Use `--where EXPR` to only process lines where the given Python expression is True.
All fields of the event are available by their key name.

```bash
$ cat httplog.txt | klp --where "len(message) > 10 and int(response[:3] > 499"
```

The whole event dict can be accessed as the underscore `_`.

By default, errors are ignored, because some keys might not be available in all lines. 
Use `--debug` to print exceptions.

This can be combined with other filters, such as `--grep` and grep context lines.

### Advanced Input Transformations Using Python Code

Use `--input-exec`/`-I` to transform events using Python code. The code is executed for each event, with all event fields available as Python variables. New fields can be created by assigning to variables, and any field can be modified or deleted.

```bash
# Create uppercase message, extract status code, and add severity level
$ klp app.log -I 'msg_upper = message.upper(); status = int(response[:3]); severity = "error" if status >= 500 else  "info"'

# Multiple transformations can be chained using additional -I options
$ klp app.log -I 'msg_upper = message.upper()' -I 'word_count = len(message.split())'

# Process line-based log, extract fields, and clean up
$ klp app.log -f line -I 'ts,level,msg = line.split(maxsplit=2); del line' -I 'level = level.strip("[]")'
```

This shows how to use Python code to transform events, create new fields through assignment, chain multiple transformations, and remove intermediate fields that are no longer needed. 
Each transformation has access to fields created by previous ones.

To read the code from a file, use a `@` prefix:

```bash
$ klp app.log -I @myscript.py
```

#### Special Variables

When using `--input-exec`/`-I`, there are three special variables available for more complex transformations.
Each has an equivalent short form using only underscores:

* `_klp_event` or `_`: Provides read-access to the current event dictionary. This is useful for keys that aren't valid Python identifiers.
* `_klp_event_add` or `__`: The contents of this dictionary will be merged into the current event.
* `_klp_events` or `___`: A list of dictionaries, where each dictionary represents an event. This lets you create multiple events from a single input event.

```bash
# Using _ to access keys with special characters
$ klp examples/qryn.jsonl -j -I "method=_['req.method'].lower()"

# Using _klp_event_add to add or update fields
$ klp app.log -I "_klp_event_add={'new_field': 'value', 'updated_field': msg.upper()}"

# Using _klp_events to generate multiple events
$ klp app.log -I "_klp_events=[{'split': word} for word in msg.split()]"
```

#### Text Column Processing with `cols()`

When using `--input-exec`/`-I`, any string value in your event (whether from the original parsed event or created during processing) can be split into columns using the `cols()` method.
This is especially useful for processing fixed-format logs or extracting information from complex field values.

Background: This method is available because the event key variables are an enhanced string type, which includes additional methods, such as `.cols()`.

```python
cols(column_spec, sep=None, outsep=" ")
```

- `column_spec`: One or more column selectors (see below)
- `sep`: Optional separator between input columns (defaults to whitespace)
- `outsep`: String used to join columns within each selector (defaults to space)

Column selectors can be:
- Single index: `"0"` or `0` (first column)
- Multiple indices: `"0,2"` (first and third columns, joined)
- Slice: `"1:3"` (second and third columns, joined)
- Negative indices: `"-2"` (second-to-last column)
- Mix of these: `"-2,2,4:"` (combines columns in each argument)

Multiple arguments return a list instead of a string.
So with Python's tuple unpacking, you can create multiple new keys from just one `cols()` call:

```bash
# Split log line into timestamp, level, and message (rest of the line)
$ klp app.log -f line -I 'ts,level,msg=line.cols("0,1", "2", "3:")'

# Extract information from a complex message field
$ klp myapp.logfmt -I 'user,action=message.cols("1,2", "3:", sep="|")'
```

Example inputs/outputs to explain the column spec syntax: 

```python
line = "alpha beta gamma delta epsilon"
line.cols(0)          # Returns "alpha"
line.cols("0,2")      # Returns "alpha gamma"
line.cols(0, 2)       # Returns ["alpha", "gamma"]
line.cols("1:3")      # Returns "beta gamma"
line.cols(1, "-2,2,4:", 3)  # Returns ["beta", "delta gamma epsilon", "delta"]
```

This method can be called on any string field in your event. 
Out-of-range indices are silently ignored, returning an empty string for invalid selections.

As a shortcut, you can just call the field, which will call the `cols()` method: 

```python
line(1, "-2,2,4:", 3)  # Returns ["beta", "delta gamma epsilon", "delta"]
```

#### Helper Functions

When using `--input-exec`, you have access to a variety of helper functions designed for common log processing tasks. The full list of available functions and modules can be viewed using `klp --help-python`.
Here are some that need more explanation:

##### `extract_regex()`

`extract_regex(pattern, text, *groupargs)`: Extract text matching a regular expression pattern, with optional capture group selection

  - `pattern`: Regular expression pattern to match
  - `text`: String to search within
  - `groupargs`: Optional indices of capture groups to extract

Returns matched text, or `None` if no match. With `groupargs`, returns tuple of matched groups.

```bash
# Extract the first number from a message
$ echo 'time=2024-02-08T15:04:05Z msg="Server CPU usage: 95.2%"' | \
  klp -I 'cpu=extract_regex(r"CPU usage: (\d+\.?\d*)%", msg, 1)'
time=2024-02-08T15:04:05Z msg="Server CPU usage: 95.2%" cpu=95.2

# Extract multiple parts from a complex message
$ echo 'time=2024-02-08T15:04:05Z msg="User alice (role=admin) accessed /api/users"' | \
  klp -I 'user,role = extract_regex(r"User (\w+) \(role=(\w+)\)", msg, 1, 2)'
time=2024-02-08T15:04:05Z msg="User alice (role=admin) accessed /api/users" user=alice role=admin
```

Like `cols()` and other helper functions, this is available as a method on the fields as well: 

```bash
# Use method syntax. Extract whole match if no groups specified 
$ echo 'time=2024-02-08T15:04:05Z msg="Request from 192.168.1.100"' | \
  klp -I 'ip=msg.extract_regex(r"\d+\.\d+\.\d+\.\d+")'
time=2024-02-08T15:04:05Z msg="Request from 192.168.1.100" ip=192.168.1.100
```

##### `parse_kv()`

`parse_kv(text, sep=None, kvsep="=")`: Parse key-value pairs from a string and merge them into the current event
  - `text`: Input string containing key-value pairs
  - `sep`: Separator between different pairs (whitespace by default)
  - `kvsep`: Separator between keys and values (defaults to "=")
  - Commonly used with `__` to add the parsed fields to the current event

```bash
# Parse query parameters into separate fields
$ echo 'time=2024-02-08T15:04:05Z msg="GET /search" query="user=alice&role=admin"' | \
  klp -I '__=parse_kv(query, sep="&")'
time="2024-02-08T15:04:05Z" msg="GET /search" query="user=alice&role=admin" user="alice" role="admin"

# Parse metrics with custom separator
$ echo 'time=2024-02-08T15:04:05Z msg="System stats" metrics="cpu:95.2 mem:87.5 disk:45.8"' | \
  klp -I '__=parse_kv(metrics, kvsep=":")'
time="2024-02-08T15:04:05Z" msg="System stats" metrics="cpu:95.2 mem:87.5 disk:45.8" cpu="95.2" mem="87.5" disk="45.8"
```

##### `parse_jsonl()`

`parse_jsonl(line)`: Returns a dictionary with key-value pairs representing the fields in the first JSON object found.
- `line`: A string that includes JSON somewhere in it.

```bash
# Example log line with JSON content
$ echo 'time=2024-02-08T15:04:05Z level=info msg="User details" data={"user_id": "12345", "action": "login"}' |   klp -f line -I '__=parse_jsonl(line)'
line="time=2024-02-08T15:04:05Z level=info msg=\"User details\" data={\"user_id\": \"12345\", \"action\": \"login\"}" user_id=12345 action=login
```

##### `sh()`

`sh(command, **kwargs)`: Execute a shell command and return its output
  - `command`: The shell command to execute
  - Returns the command's stdout as a string (stripped of trailing whitespace)
  - Raises an exception if the command fails (disable with `check=False`)
  - Can be customized with subprocess.run keyword arguments

```bash
# Add git commit info to each event
$ echo 'time=2024-02-08T15:04:05Z level=info msg="Deployment started"' | \
  klp -I '__={"git_rev": sh("git rev-parse HEAD")[:7]}'
time=2024-02-08T15:04:05Z level=info msg="Deployment started" git_rev=62efbb3

# Add system load information
$ echo 'time=2024-02-08T15:04:05Z level=info msg="Health check"' | \
  klp -I '__={"load": sh("uptime").split("load average:")[-1].strip()}'
```

Note: Use the `sh()` function carefully, and only with trusted input to avoid command injection vulnerabilities.

### Custom Output Formatting using Python

For advanced output formatting, use `--output-template` (with Python f-strings) or `--output-eval` which allows Python code:

```bash
$ klp --output-template "{format_datetime(timestamp)} - {extract_ipv4(message) or 'no IP'}" app.log
$ klp --output-eval "f'{ts} {pprint_json(data)}'" app.log
```

Several Python modules can be used in output expressions.
Use `--help-python` to show the list of available modules and functions.

The following additional functions are available:

* `extract_json()`: return the first JSON object or array in a given string as a string
* `extract_email()`: return the first email address in a given string
* `extract_fqdn()`: return the first FQDN in a given string
* `extract_ipv4()`: return the first IPv4 address in a given string
* `extract_regex()`: return first part of the string matching a regex
* `extract_url()`: return the first URL in a given string
* `format_datetime()`: format given string according to ISO 8601 (with millisecond precision), guessing the datetime format  
* `guess_datetime()`: convert a string into a Python datetime object
* `pprint_json()`: pretty print JSON data


### Parsing Non-Line-Based Formats with `-f data`

The `-f data` option reads the entire input as a single string into a field named `data`.
This is particularly useful for creating ad-hoc parsers for formats that aren't naturally line-based, using `--input-exec` to transform the content.

For example, to parse a simple Windows-style INI file:

```bash
$ cat config.ini
[database]
host = localhost
port = 5432

[api]
url = https://api.example.com
key = secret123

$ klp -f data config.ini -I '___ = [{"section": s.split("\n")[0].strip("[]"),
                                    **dict(l.split(" = ") for l in s.split("\n")[1:] if "=" in l)}
                                   for s in data.split("\n[")]'
section=database host=localhost port=5432
section=api url=https://api.example.com key=secret123
```

The key advantage of `-f data` is maintaining the complete file context, which makes it easier to split the content on the correct boundaries and extract related information that spans multiple lines.
Combined with Python's string manipulation functions and regular expressions, this allows quick creation of parsers for various structured formats.


## Additional Resources

### Complementary Tools

These tools aren't specialized for log files but are useful to post-process or view klp's output, particularly the JSONL or TSV formats:

#### General Purpose Data Processing
- [jq](https://jqlang.github.io/jq/): A lightweight and flexible command-line JSON processor
- [jaq](https://github.com/01mf02/jaq): A jq clone focussed on correctness, speed, and simplicity
- [yq](https://github.com/mikefarah/yq): A portable command-line YAML, JSON, XML, CSV, TOML and properties processor
- [Miller](https://github.com/johnkerl/miller): Like awk, sed, cut, join, and sort for name-indexed data such as CSV, TSV, and tabular JSON 
- [dasel](https://github.com/TomWright/dasel): Select, put and delete data from JSON, TOML, YAML, XML and CSV files with a single tool. Supports conversion between formats

#### CSV Processing
- [qsv](https://github.com/jqnatividad/qsv): CSVs sliced, diced & analyzed
- [csvlens](https://github.com/YS-L/csvlens): Command line csv viewer

#### Format Conversion and Viewing
- [jc](https://github.com/kellyjonbrazil/jc): CLI tool and python library that converts the output of popular command-line tools, file-types, and common strings to JSON, YAML, or Dictionaries
- [jtbl](https://github.com/kellyjonbrazil/jtbl): CLI tool to convert JSON and JSON Lines to terminal, CSV, HTTP, and markdown tables
- [ov](https://github.com/noborus/ov): Feature-rich terminal-based text viewer. It is a so-called terminal pager.
- [Visidata](https://www.visidata.org): A terminal spreadsheet multitool for discovering and arranging data
- [Benthos](https://github.com/benthosdev/benthos.git): High performance and resilient stream processor, able to connect various sources and sinks

#### Processing TSV Output
The TSV format can be processed by spreadsheet software and common Unix tools:

- [cut](https://man7.org/linux/man-pages/man1/cut.1.html): Uses tab separator by default
- [AWK](https://man7.org/linux/man-pages/man1/awk.1p.html): `-F$'\t'`
- [sort](https://man7.org/linux/man-pages/man1/sort.1.html): `-t$'\t'`
- [column](https://man7.org/linux/man-pages/man1/column.1.html): `-s$'\t' -N timestamp,log_level,message -J` (can convert to JSON)
- [Vim](https://www.vim.org): `:set list    :set listchars=tab:>-`
- [Pandas](https://pandas.pydata.org): `pd.read_table()`
- [SQLite](https://www.sqlite.org):
```sql
sqlite> .mode tabs
sqlite> .import data.tsv data
sqlite> select date(timestamp) as day, count(*) from data group by day;
```

### Alternative Tools

If klp doesn't meet your needs, here are some alternatives:

#### Logfmt CLI/TUI
- [hutils](https://github.com/brandur/hutils): The original logfmt tools (Ruby)
- [lfq](https://github.com/mattcontinisio/lfq): Command-line logfmt processor (Go). Quite similar to klp. Faster, but fewer features
- [angle-grinder](https://github.com/rcoh/angle-grinder): Slice and dice logs on the command line (Rust). Flexible query syntax
- [pq](https://github.com/iximiuz/pq): Parse and Query log files as time series
- [Kelpie](https://github.com/Yord/klp): Small, fast, and magical command-line data processor similar to pxi, jq, mlr, and awk
- [lnav](https://github.com/tstack/lnav): Very advanced log file viewer. Files-only (no streaming), lots of formats

#### JSON CLI/TUI
- [fblog](https://github.com/brocode/fblog): Small command-line JSON Log viewer (Rust). Lua filters.
- [json-log-viewer](https://github.com/gistia/json-log-viewer): Powerful terminal based viewer for JSON logs using ncurses (JavaScript). TUI
- [Toolong](https://github.com/Textualize/toolong): A terminal application to view, tail, merge, and search log files, plus JSONL (Python). TUI
- [sumoshell](https://github.com/SumoLogic/sumoshell): Collection of utilities to improve analyzing log files (Go). Successor is angle-grinder.
- [l'oGGo](https://github.com/aurc/loggo): A powerful terminal app for structured log streaming (Go). TUI
- [hl](https://github.com/pamburus/hl): A log viewer that translates JSON logs into human-readable representation (Rust)
- [logdissect](https://github.com/dogoncouch/logdissect.git): CLI utility and Python module for analyzing log files and other data (Python). Multiple input formats

#### Unstructured Logs CLI/TUI
- [tailspin](https://github.com/bensadeh/tailspin): A log file highlighter (Rust)
- [GoAccess](https://goaccess.io): Real-time web log analyzer and interactive viewer that runs in a terminal in *nix systems or through your browser

#### Web UI
- [Klogg](https://github.com/variar/klogg): Multi-platform GUI application that helps browse and search through long and complex log files
- [frontail](https://github.com/mthenw/frontail/): Streaming logs to the browser
- [LogScreen](https://github.com/soorajshankar/logScreen): Loglines can be messy, read it better on a browser, `command | npx logscreen`
- [Logdy](https://logdy.dev): Web based real-time log viewer. Stream ANY content to a web UI with autogenerated filters. Parse any format with TypeScript

#### Large Scale Solutions
- [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/): Fast, resource-efficient log database with full-text search, LogsQL querying, and seamless Unix tool integration.
- [OpenObserve](https://github.com/openobserve/openobserve): Cloud-native observability platform built specifically for logs, metrics, traces, analytics, RUM, designed to work at petabyte scale
- [Graylog](https://github.com/Graylog2/graylog2-server): Free and open log management
- [Grafana Loki](https://grafana.com/docs/loki/latest/visualize/grafana/): Horizontally-scalable, highly-available, multi-tenant log aggregation system