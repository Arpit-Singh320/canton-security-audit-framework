# Changelog — Canton Security Audit Framework

## [0.3.0] — 2026-04-03

### Added
- Authority leak detector (`analyzer/rules/authority_leak.py`) with false-positive reduction
- Choice abuse detector for unbounded recursive choices
- Time-attack detector for time-sensitive choice vulnerabilities
- Disclosure detector for unintended observer exposure
- SARIF + JSON report generator for CI integration
- Reusable GitHub Actions workflow (`daml-audit.yml`) for PR scanning
- CI pipeline with test contract validation
- `DAML_TOP_10.md` — Canton equivalent of OWASP Smart Contract Top 10
- `AUDIT_METHODOLOGY.md` — formal review procedure for Canton auditors
- Unit tests for all 4 detection rules

## [0.2.0] — 2026-03-20

### Added
- Main analyser CLI (`analyzer/main.py`)
- Daml AST parser extracting templates, choices, signatories, observers

## [0.1.0] — 2026-03-14

### Added
- Initial project scaffolding, README, daml.yaml, .gitignore
