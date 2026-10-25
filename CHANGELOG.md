# Changelog

## 0.2.0 — 2026-10-25

### Added

- Interactive scan setup with `--interactive`.
- Terminal progress, an animated spinner, colored verdicts, and a final scan summary.
- Document-type filters with `--extensions` and input-size limits with `--max-size-mb`.
- Report selection with repeatable `--format`, custom `--output-dir`, and a combined JSON manifest with `--batch-report`.
- Explicit `--offline` mode and per-service/per-indicator reputation statuses in reports.
- Three README animations with static alternatives and reproducible artwork generation.
- Installable `ioc-inspector` command, bundled report schema, and declared runtime dependencies.

### Fixed

- VirusTotal URL identifier encoding and request pacing across scan threads.
- Missing standalone PDF IP addresses and JavaScript actions in object dictionaries.
- Missing Office XML text and relationship indicators, RTF handling, and VBA keyword labels.
- Report filename collisions, ignored export formats, quiet/debug behavior, and batch failures that stopped later documents.

### Changed

- Directory scans now skip unsupported files, generated reports, output/log folders, virtual environments, and repository metadata.
- Inputs default to a 50 MiB size limit; `--max-size-mb 0` disables it.
- Reports and logs default to the working directory. Existing `--report` and `--json` switches remain supported.
- Missing or failed reputation checks are explicit and do not by themselves change the exit code. Heuristic verdicts remain triage signals, not safety guarantees.

### Validation

- 80 tests pass with 94% core coverage; lint and type checks pass.
- GitHub CI validates Python 3.10 and 3.11 on Linux and Windows.
- Packaged CLI checks cover offline scans, all five export formats, interactive setup, and batch error handling.

[Changes since v0.1.0](https://github.com/PKHarsimran/IOC-Inspector/compare/v0.1.0...v0.2.0)
