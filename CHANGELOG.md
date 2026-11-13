# Changelog

All notable changes to NoxaPlus EnvSentinel are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-13

First public release.

### Added

- `envsentinel [scan] [paths...]` — scan files or directories for leaked credentials and risky configuration. Tree mode respects a built-in ignore list for VCS metadata, dependencies, build output, lockfiles, minified assets, media, and archives.
- 27 rules across provider tokens, credential shapes, sensitive files, and high-entropy strings, with `envsentinel rules` listing IDs, severities, and descriptions.
- `--staged` mode that reads the git index (`git diff --cached` plus `git show :path`), so the scan checks exactly what the commit will contain.
- Shannon entropy detection for unclassified secrets, with configurable threshold and minimum length, and `--no-entropy` to turn it off.
- Placeholder filtering for obvious examples, environment references, and template expressions.
- Inline suppression with `envsentinel:ignore`, `envsentinel:ignore-next-line`, and optional rule IDs.
- Masked output: every reported value is shortened to a recognizable prefix and suffix before it reaches text, JSON, or SARIF.
- Text reports grouped by file with severity colors, line and column, rule ID, and a human-readable explanation, plus a per-severity summary and rotation advice.
- `--format json` for a stable machine-readable report.
- `--format sarif` for SARIF 2.1.0 with all rule metadata, severity levels, `security-severity` scores, and stable fingerprints for GitHub code scanning.
- `envsentinel install-hook` to install a pre-commit hook that runs `scan --staged --fail-on high`. The installer refuses to overwrite hooks it did not write; `--force` replaces them.
- `.envsentinel.json` configuration for `ignorePaths`, `ignoreRules`, `allowPatterns`, `entropyThreshold`, `entropyMinLength`, and `maxFileSizeKb`, with validation and clear errors.
- `--out` to write reports to a file, `--fail-on` for a configurable exit threshold, `--exclude` for repeatable globs, `--no-color`, and `--quiet`.
- Deliberate exit codes: `0` clean, `1` findings at or above the threshold, `2` usage, config, path, or git errors.
- Programmatic API exported from the package entry point: scanning, rules, config, SARIF, and hook installation.
- Test suite covering entropy, every rule, scanner behavior, config parsing and globbing, git integration, SARIF output, and the CLI. Fixtures build fake secrets at runtime so the repository scans cleanly.

### Known limits

- Pattern matching and entropy are heuristics; a clean scan is not proof that no secret exists.
- Binary files, lockfiles, and files over 1 MiB are skipped.
- Staged mode requires a git repository and does not scan untracked files.
- EnvSentinel never removes secrets or rewrites history. Rotation and history cleanup remain manual.
