# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New rule `DAML-VULN-011`: Detection of inefficient list operations (`map`, `concat`, etc.) in choices that can lead to high transaction costs or latency.
- Support for analyzing multi-package Daml projects defined in a `multi-package.yaml` file.
- The `--config` CLI option to specify a custom rules configuration file, allowing teams to enable/disable specific rules.

### Changed
- Improved accuracy of `DAML-VULN-003` (Leaked Signatory Authority) to reduce false positives in common delegation and role-based access control patterns.
- Updated documentation to reflect best practices for Canton 3.4.

### Fixed
- Resolved an issue where analysis would fail on Daml projects containing empty `daml.yaml` files.

## [0.2.0] - 2024-05-20

### Added
- **New Vulnerability Detection Rules**:
    - `DAML-VULN-008`: Unsafe Use of `getTime` for Business Logic (Time-based Attacks).
    - `DAML-VULN-009`: Missing `ensure` clauses on critical numeric fields (e.g., ensuring `amount > 0.0`).
    - `DAML-VULN-010`: Potential Replay Attack Vulnerability via Non-Consuming Choices.
- **SARIF Output Format**: Added `--output-format sarif` for seamless integration with GitHub Advanced Security code scanning and other SAST platforms.
- **Python API**: Introduced a public Python API for programmatic analysis, enabling integration into custom development and security scripts.

### Changed
- **BREAKING**: The default CLI output format is now a structured plain text format for improved readability and easier parsing. The old format is available via `--output-format legacy`.
- Optimized the contract graph traversal algorithm, resulting in a ~30% performance improvement on large, complex codebases.

### Fixed
- Fixed a parsing error for Daml projects utilizing newer SDK features like generic `interface` views.
- The tool now correctly identifies observers that are defined transitively through interface implementations.

## [0.1.0] - 2024-04-15

### Added
- Initial release of the Canton Security Audit Framework (`daml-audit`).
- Command-line tool for scanning compiled Daml `.dar` archives for security vulnerabilities.
- **Initial Set of 7 Core Vulnerability Rules**:
    - `DAML-VULN-001`: Insecure Direct Authority
    - `DAML-VULN-002`: Missing Signatory/Observer Checks in `fetch` and `archive`
    - `DAML-VULN-003`: Leaked Signatory Authority
    - `DAML-VULN-004`: Improper Choice Authorization
    - `DAML-VULN-005`: Data Disclosure to Unauthorized Observers
    - `DAML-VULN-006`: Incorrect Archival Logic (e.g., archiving without replacement)
    - `DAML-VULN-007`: Lack of Input Validation in choice arguments.
- Core documentation: `DAML_TOP_10.md` and `AUDIT_METHODOLOGY.md`.
- Example GitHub Actions workflow (`daml-audit.yml`) for integrating automated scans into CI/CD pipelines.
- Foundational test suite covering all included analysis rules.