# Changelog

## v0.76.2 - 2025-02-08

### Added

* **New Feature:** Added normalization feature (`--normalize`), replacing common patterns with placeholders to hide duplicates.
* Added support for detecting failure-related events via a `fail` regex and expanded cases.
* Added unit tests for IPv4/IPv4 port regexes.
* Added a note about default input format in the README.

### Changed

* README: Moved note about default input format up to the quickstart section.

### Fixed

* Fixed IPv6 and IPv4 regexes.
* Fixed unit tests for the `fail` regex.
* Fixed the unit tests for changed `sanitize_key()`.
* Fixed the release workflow.
* Fixed outdated unreleased diff link.

---

## v0.76.1 - 2025-02-03

### Added

* **New Feature:** Added support for RFC 5424 syslog (`-f rfc5424`, `-f syslog`).
* Added another datetime format found in the wild.

### Changed

* `tsNlm` parsers now ignore some special characters to better recognize log levels.
* Enhanced structured data extraction from RFC 5424 logs.

### Fixed

* Fixed minor formatting issues in README.

---

## v0.76.0 - 2025-01-23

### Added

* **New Feature:** Added `--loglevel-key` option to specify the key for log levels.
* Added additional datetime formats for better timestamp parsing.

### Changed

* Reformatted the code using `black`.

### Fixed

* Fixed test fixtures.

---

## v0.75.1 - 2025-01-19

### Changed

* Only one message key is now used for CLEF.

---

## v0.75.0 - 2025-01-18

### Added

* Added default CLEF keys.
* Added support for `log4j` input format.
* Added `kl` interactive Kubernetes log viewer to the alternative tools.

### Changed

* Updated release script to follow a GitHub Flow lite approach with a "dev" branch.

### Fixed

* Fixed grammar issues in documentation.

---

## v0.74.5 - 2025-01-09

### Fixed

* Fixed streaming tests for Windows.

---

## v0.74.4 - 2025-01-09

### Fixed

* Fixed release.yml workflow.

---

## v0.74.3 - 2025-01-09

### Added

* Added release tests for Windows, Mac, and Linux (Python 3.7 - 3.13).

---

## v0.74.2 - 2025-01-09

### Fixed

* Fixed AttributeError on Windows (#3).

---

## v0.74.1 - 2025-01-04

### Added

* Added `config.ini` support for setting defaults and aliases.
* Added options to `split_endswith()` and `split_startswith()` for better event splitting.

### Changed

* Refactored handling of `--logical-lines` as an input option.

### Fixed

* Fixed SQL regex.
* Fixed timestamp quoting issues.

---

## v0.74.0 - 2025-01-04

### Added

* Added `generate_incident.py` tool to generate example logs.
* Added `incident75k.logfmt.zip` example log file.

---

## v0.73.1 - 2025-01-03

### Fixed

* Fixed `--fuse` behavior for time gaps between single events.
* Fixed BrokenPipe error when piping output to `head`.

---

## v0.73.0 - 2024-12-18

### Added

* **New Feature:** Added `EStr.before()`, `.after()`, and `.between()` methods for easier string manipulation.

### Fixed

* Fixed EStr.cols() docstring examples.

---

## v0.72.0 - 2024-11-18

### Added

* Added workflow to run tests on all commits.
* Added example file (`email_custom.log.gz`) demonstrating GZip support.
* **New Feature:** Added error handling options (`--error ignore|print|exit`).

### Changed

* Renamed `--error` to `--errors`.

### Fixed

* Fixed failing streaming test.

---

## v0.71.1 - 2024-11-16

### Changed

* Process multiple files in mtime-order (oldest first).

---

## v0.71.0 - 2024-11-10

### Added

* **New Feature:** Added `--parallel` input parsing for line-based formats to improve performance.
* Added `--mark-gaps` and `--fuse` examples in the documentation.

### Fixed

* Fixed exception in `colored_mapchar()`.
* Fixed `--output-tablename` handling.

---

## v0.70.9 - 2024-11-10

### Fixed

* Fixed minor layout issues in documentation.

---

## v0.70.8 - 2024-11-08

### Changed

* `pyproject.toml` now gets its version from `klp.py` to maintain consistency.

### Fixed

* Fixed release workflow.

---

## v0.70.7 - 2024-11-08

### Added

* Added version consistency check for `pyproject.toml`.
* Added combined GitHub and PyPI release workflows.

---

## v0.70.6 - 2024-10-22

### Added

* Added GitHub action for releases.
* Added PyPI release workflow.

---

