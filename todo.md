- Input formats
    * -f cef
    * -f syslog
    * -f mbox
    * -f xml
    * formats from logdissect.py, https://docs.logz.io/docs/user-guide/data-hub/log-parsing/default-parsing/
    * Input format guessing? (probably too error-prone)
- Output formats
    * -F yaml  (simple)
    * -F xml
    * Allow to specify output encoding (fix commit 9698a8b9)
- Utility functions
    * llm() # batch handling of multiple lines
    * render_file(template_path)
- Stats
    * Continuously displaying the current message rate (sliding window or exponentail moving average)
- Performance
    * fast paths (simple output, no color, ...)
- Other features
    * --errors ignore|print|exit
    * --grepmap just showing if a line matches
    * --gapmap showing the unit of the timegap (u,s,m,h,D,M,Y)
    * --grep-time-context (context by timespan, not number of lines)
    * --query SQL
    * Highlighting regex matches
    - Add TUI with textual
- README and help
    * Document how to use -f data together with -I
    * Document --logical-lines
    * Add common use cases
    * How to use complementary tools: jc, sqlite, jq, ...
    * Add --manual with examples
- Infrastructure
    * Nice logo
    * Autocompletion for bash
    * Standalone executable (e.g. with Nuitka)
- Bug fixes, performance, stability
    * Synthetic fields not shown if no other keys specified
    * Problems with multiple files in ZIP archives
    * Fix grep when used both with and without keys
    * Use fast string comparison for ISO dates
    * More robust logfmt parsing: Allow fields (e.g. timestamps) without quotes that have whitespace in them
    * Rewrite in Rust :-)
    