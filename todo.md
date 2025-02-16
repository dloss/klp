- Bug fixes, robustness
    * Compare datetime parsing against dateutil.parser
    * Stricter logfmt parser
    * Synthetic fields not shown if no other keys specified
    * Problems with multiple files in ZIP archives
    * Fix grep when used both with and without keys
    * Let -z transform the event, not only the default output 
- Input formats
    * -f mbox
    * -f xml
    * lnav formats (BSD license)
    * formats from logdissect.py, https://docs.logz.io/docs/user-guide/data-hub/log-parsing/default-parsing/
    * Input format guessing? (probably too error-prone)
- Output formats
    * Allow to specify output encoding (fix commit 9698a8b9)
    * -F yaml  (simple)
    * -F xml
- Utility functions
    * llm() # batch handling of multiple lines
    * render_file(template_path)
- Stats
    * Continuously displaying the current message rate (sliding window or exponentail moving average)
- Performance
    * fast paths (simple output, no color, ...)
- Other features
    * --grepmap just showing if a line matches
    * --gapmap showing the unit of the timegap (u,s,m,h,D,M,Y)
    * --grep-time-context (context by timespan, not number of lines)
    * --query SQL
    * Highlighting regex matches
    - Add TUI with textual
- README and help
    * Document how to use -f data together with -I
    * Document EStr.before/after/between()
    * Add common use cases
    * How to use complementary tools: jc, sqlite, jq, ...
    * Add --manual with examples
    * Demo videos
    * llms.txt
    * k9s plugin
- Distribution
    * zipapp
    * Debian package
    * pyoxy
    * Docker image (probably overkill)
- Infrastructure
    * Nice logo
    * Changelog
    * Autocompletion for bash
    * Standalone executable (e.g. with Nuitka)
- Performance
    * Benchmarks, e.g. using hyperfine
    * Use fast string comparison for ISO dates
    * Rewrite in Rust :-)
    