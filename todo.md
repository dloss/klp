- Input formats
    * -f syslog
    * -f mbox
    * -f xml
    * formats from logdissect.py, https://docs.logz.io/docs/user-guide/data-hub/log-parsing/default-parsing/
    * Input format guessing
- Output formats
    * -F yaml  (simple)
    * -F xml
    * Allow to specify output encoding
- Utility functions
    * sh()
    * llm()
    * render_file(template_path)
- Stats
    * Continuously displaying the current message rate (sliding window or exponentail moving average)
- Other features
    * --grepmap just showing if a line matches
    * --gapmap showing the unit of the timegap (u,s,m,h,D,M,Y)
    * --grep-time-context (context by timespan, not number of lines)
    * --query SQL
    * Highlighting regex matches
    - Add TUI with textual
- README and help
    * Document --mark-gaps and --fuse
    * Document --utc and --localtime
    * Document double and triple underscore handling for --input-exec
    * Document parse_kv()
    * Document --output-file
    * Document --keymap
    * Document sh()
    * Add common use cases
    * How to use complementary tools: jc, sqlite, jq, ...
    * Add --manual with examples
- Infrastructure
    * Publish on PyPI
    * Nice logo
    * Autocompletion for bash
    * Standalone executable (e.g. with Nuitka)
- Bug fixes, performance, stability
    * Fix grep when used both with and without keys
    * Use fast string comparison for ISO dates
    * More robust logfmt parsing: Allow fields (e.g. timestamps) without quotes that have whitespace in them
    * Rewrite in Rust :-)
    