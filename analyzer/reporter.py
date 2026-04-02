# canton-security-audit-framework/analyzer/reporter.py

"""
Generates analysis reports in various formats (JSON, SARIF).

This module takes a list of vulnerability findings from the analyzer
and formats them into machine-readable reports suitable for CI/CD
integration and further processing.
"""

import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

# A dictionary containing metadata for each analysis rule.
# This is used to populate the SARIF report with rich information.
RULE_METADATA = {
    "authority_leak": {
        "name": "AuthorityLeak",
        "shortDescription": {
            "text": "Improper delegation of signatory or choice authority."
        },
        "fullDescription": {
            "text": "A contract choice incorrectly grants authority to a party that should not possess it, potentially allowing unauthorized actions. This often happens when a choice controller set includes parties who are not signatories of the resulting contract."
        },
        "helpUri": "https://docs.daml.com/daml/security/contract-model.html#authority",
        "properties": {
            "tags": ["security", "authorization", "daml"],
            "precision": "high"
        }
    },
    "choice_abuse": {
        "name": "ChoiceAbuse",
        "shortDescription": {
            "text": "Non-consuming choice allows for potential resource exhaustion."
        },
        "fullDescription": {
            "text": "A non-consuming choice can be exercised repeatedly without archiving the contract, which may lead to unintended state changes, resource exhaustion attacks (e.g., creating infinite contracts), or denial-of-service."
        },
        "helpUri": "https://docs.daml.com/daml/security/contract-model.html#consuming",
        "properties": {
            "tags": ["security", "denial-of-service", "daml"],
            "precision": "medium"
        }
    },
    "time_attack": {
        "name": "TimeSensitiveAttack",
        "shortDescription": {
            "text": "Usage of time-dependent functions may be vulnerable to manipulation."
        },
        "fullDescription": {
            "text": "Smart contracts relying on `getTime` are susceptible to time-based attacks, as the submitter of a command can influence the ledger time within a certain window. This can be exploited in time-sensitive logic, such as options expiry or deadlines."
        },
        "helpUri": "https://docs.daml.com/daml/security/time.html",
        "properties": {
            "tags": ["security", "time-dependency", "daml"],
            "precision": "high"
        }
    },
    "disclosure": {
        "name": "ImproperDisclosure",
        "shortDescription": {
            "text": "Sensitive data may be disclosed to unauthorized observers."
        },
        "fullDescription": {
            "text": "A contract's observer set includes parties who should not have access to the contract's data. This can lead to information leaks, as all observers can see the full contract payload."
        },
        "helpUri": "https://docs.daml.com/daml/security/privacy.html#observers",
        "properties": {
            "tags": ["security", "privacy", "disclosure", "daml"],
            "precision": "high"
        }
    }
}


@dataclass
class Finding:
    """Represents a single vulnerability or issue found by the analyzer."""
    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    severity: str  # 'error', 'warning', 'note'


def generate_json_report(findings: List[Finding], output_path: str) -> None:
    """
    Generates a simple JSON report from a list of findings.

    Args:
        findings: A list of Finding objects.
        output_path: The file path to write the JSON report to.
    """
    report_data = [asdict(f) for f in findings]
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        print(f"Successfully generated JSON report at {output_path}")
    except IOError as e:
        print(f"Error writing JSON report to {output_path}: {e}")


def generate_sarif_report(findings: List[Finding], output_path: str, tool_version: str = "0.1.0") -> None:
    """
    Generates a SARIF 2.1.0 report for CI/CD integration.

    Args:
        findings: A list of Finding objects.
        output_path: The file path to write the SARIF report to.
        tool_version: The version of the analysis tool.
    """
    rules = []
    for rule_id, meta in RULE_METADATA.items():
        rules.append({
            "id": rule_id,
            **meta
        })

    results = []
    for finding in findings:
        # Map severity to SARIF level
        level = "warning"
        if finding.severity == "error":
            level = "error"
        elif finding.severity == "note":
            level = "note"

        results.append({
            "ruleId": finding.rule_id,
            "message": {"text": finding.message},
            "level": level,
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.file_path
                    },
                    "region": {
                        "startLine": finding.start_line,
                        "startColumn": finding.start_column,
                        "endLine": finding.end_line,
                        "endColumn": finding.end_column
                    }
                }
            }]
        })

    sarif_log = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Canton Security Audit Framework",
                    "version": tool_version,
                    "informationUri": "https://github.com/digital-asset/canton-security-audit-framework",
                    "rules": rules
                }
            },
            "results": results
        }]
    }

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_log, f, indent=2)
        print(f"Successfully generated SARIF report at {output_path}")
    except IOError as e:
        print(f"Error writing SARIF report to {output_path}: {e}")

if __name__ == '__main__':
    # Example usage for demonstration and testing purposes
    print("Running reporter module demonstration...")

    # Create some dummy findings
    dummy_findings = [
        Finding(
            rule_id="authority_leak",
            message="Signatory of resulting contract 'UserRole' is not a controller of choice 'GrantAdmin'.",
            file_path="daml/User.daml",
            start_line=25,
            start_column=5,
            end_line=30,
            end_column=6,
            severity="error"
        ),
        Finding(
            rule_id="disclosure",
            message="Party 'auditor' is an observer but not a signatory, potentially leaking trade details.",
            file_path="daml/Trade.daml",
            start_line=42,
            start_column=15,
            end_line=42,
            end_column=30,
            severity="warning"
        ),
        Finding(
            rule_id="time_attack",
            message="Use of 'getTime' can be manipulated by the command submitter.",
            file_path="daml/Option.daml",
            start_line=78,
            start_column=12,
            end_line=78,
            end_column=20,
            severity="error"
        )
    ]

    # Generate reports
    generate_json_report(dummy_findings, "daml-analysis-report.json")
    generate_sarif_report(dummy_findings, "daml-analysis-report.sarif")

    print("\nDemonstration complete. Check for 'daml-analysis-report.json' and 'daml-analysis-report.sarif'.")