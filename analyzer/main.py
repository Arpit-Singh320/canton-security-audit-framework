#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import List, Dict, Set

# Define severity levels for prioritizing findings
SEVERITY_LEVELS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

class Vulnerability:
    """Represents a single vulnerability finding."""
    def __init__(self, file_path: str, line_num: int, code: str, rule_id: str, description: str, severity: str):
        self.file_path = file_path
        self.line_num = line_num
        self.code = code.strip()
        self.rule_id = rule_id
        self.description = description
        self.severity = severity

    def to_dict(self) -> Dict:
        """Serializes the vulnerability to a dictionary for JSON output."""
        return {
            "file": self.file_path,
            "line": self.line_num,
            "code": self.code,
            "ruleId": self.rule_id,
            "description": self.description,
            "severity": self.severity,
        }

    def __str__(self) -> str:
        """Provides a human-readable string representation."""
        return f"[{self.severity}] {self.rule_id} at {self.file_path}:{self.line_num}\n  -> {self.description}\n     `{self.code}`"

# --- Analysis Rules ---

def check_unsafe_get_time(lines: List[str], file_path: str) -> List[Vulnerability]:
    """
    Rule: CS-TIME-01
    Identifies usage of `getTime`, which can be manipulated by a malicious participant node operator.
    Time in a distributed system is not reliable and should not be sourced from a single counterparty's node.
    """
    findings = []
    for i, line in enumerate(lines):
        if re.search(r'\bgetTime\b', line):
            findings.append(Vulnerability(
                file_path=file_path,
                line_num=i + 1,
                code=line,
                rule_id="CS-TIME-01",
                description="Usage of `getTime` is discouraged. The time is provided by the participant node and may not be trustworthy. Consider using an oracle or a time value agreed upon by signatories.",
                severity="HIGH"
            ))
    return findings


def check_archival_control(lines: List[str], file_path: str) -> List[Vulnerability]:
    """
    Rule: CS-AUTH-01
    Checks if an archival choice is controlled by all signatories of the contract.
    If not, a minority of signatories (or even a non-signatory) could archive the contract against the will of others.
    """
    findings = []
    in_template_block = False
    template_signatories: Set[str] = set()
    
    in_choice_block = False
    choice_controllers: Set[str] = set()
    choice_archives_self = False
    choice_start_line = 0
    choice_line_content = ""

    for i, line in enumerate(lines):
        line_strip = line.strip()

        if line_strip.startswith("template"):
            in_template_block = True
            template_signatories = set()
            in_choice_block = False

        if not in_template_block:
            continue

        signatory_match = re.search(r'^\s*signatory\s+(.*)', line)
        if signatory_match:
            parties = re.split(r'[,\s]+', signatory_match.group(1))
            template_signatories.update(p for p in parties if p and p != "{" and p != "}")

        if line_strip.startswith("choice"):
            if in_choice_block and choice_archives_self and not template_signatories.issubset(choice_controllers):
                findings.append(Vulnerability(
                    file_path=file_path, line_num=choice_start_line, code=choice_line_content, rule_id="CS-AUTH-01",
                    description=f"Choice archives contract but not all signatories are controllers. Signatories: {sorted(list(template_signatories))}, Controllers: {sorted(list(choice_controllers))}. This can lead to unauthorized archival.",
                    severity="CRITICAL"
                ))
            
            in_choice_block = True
            choice_controllers = set()
            choice_archives_self = False
            choice_start_line = i + 1
            choice_line_content = line

        if not in_choice_block:
            continue

        controller_match = re.search(r'^\s*controller\s+(.*)\s+do', line)
        if controller_match:
            parties = re.split(r'[,\s]+', controller_match.group(1))
            choice_controllers.update(p for p in parties if p)
        
        if re.search(r'\barchive\s+self\b', line):
            choice_archives_self = True

    if in_choice_block and choice_archives_self and not template_signatories.issubset(choice_controllers):
         findings.append(Vulnerability(
            file_path=file_path, line_num=choice_start_line, code=choice_line_content, rule_id="CS-AUTH-01",
            description=f"Choice archives contract but not all signatories are controllers. Signatories: {sorted(list(template_signatories))}, Controllers: {sorted(list(choice_controllers))}. This can lead to unauthorized archival.",
            severity="CRITICAL"
        ))

    return findings


def check_observer_disclosure(lines: List[str], file_path: str) -> List[Vulnerability]:
    """
    Rule: CS-DISC-01
    Warns about complex observer expressions which might unintentionally leak data.
    """
    findings = []
    for i, line in enumerate(lines):
        observer_match = re.search(r'^\s*observer\s+(.*)', line)
        if observer_match:
            observer_expr = observer_match.group(1).strip()
            # Heuristic: if expression contains functions, list comprehensions, or other logic, flag it for review.
            if any(c in observer_expr for c in ['map', 'filter', '=>', 'if', 'else']):
                 findings.append(Vulnerability(
                    file_path=file_path,
                    line_num=i + 1,
                    code=line,
                    rule_id="CS-DISC-01",
                    description=f"Complex observer expression detected: `{observer_expr}`. Review carefully to ensure it doesn't leak confidential data to unintended parties.",
                    severity="MEDIUM"
                ))
    return findings

# --- Main Analyzer Logic ---

ANALYSIS_RULES = [
    check_unsafe_get_time,
    check_archival_control,
    check_observer_disclosure,
]

def analyze_file(file_path: Path) -> List[Vulnerability]:
    """Runs all analysis rules on a single Daml file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}", file=sys.stderr)
        return []

    findings = []
    for rule in ANALYSIS_RULES:
        try:
            findings.extend(rule(lines, str(file_path)))
        except Exception as e:
            print(f"Error running rule {rule.__name__} on {file_path}: {e}", file=sys.stderr)
    
    return findings

def analyze_project(project_path: Path) -> List[Vulnerability]:
    """Finds all Daml files in a project and analyzes them."""
    daml_source_path = project_path / 'daml'
    if not daml_source_path.is_dir():
        print(f"Error: `daml` source directory not found in {project_path}", file=sys.stderr)
        return []

    all_findings = []
    daml_files = list(daml_source_path.glob('**/*.daml'))

    if not daml_files:
        print(f"Warning: No .daml files found in {daml_source_path}", file=sys.stderr)
        return []

    print(f"Analyzing {len(daml_files)} Daml file(s)...")
    for daml_file in daml_files:
        all_findings.extend(analyze_file(daml_file))
    
    return sorted(all_findings, key=lambda v: (v.file_path, v.line_num))

# --- Output Formatting ---

def print_text_output(findings: List[Vulnerability]):
    """Prints findings in a human-readable format."""
    if not findings:
        print("\n✅ No vulnerabilities found.")
        return

    print(f"\n🚨 Found {len(findings)} potential vulnerabilities:")
    print("-" * 60)
    for finding in findings:
        print(finding)
        print("-" * 60)

def print_json_output(findings: List[Vulnerability]):
    """Prints findings as a JSON object."""
    output = [f.to_dict() for f in findings]
    print(json.dumps(output, indent=2))

# --- CLI ---

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Canton Security Analyzer - A static analysis tool for Daml smart contracts."
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the Daml project directory."
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format for the analysis results."
    )
    parser.add_argument(
        "--fail-on-level",
        choices=SEVERITY_LEVELS.keys(),
        default="MEDIUM",
        help="Return a non-zero exit code if a vulnerability of this level or higher is found."
    )

    args = parser.parse_args()
    project_path = Path(args.path).resolve()

    if not project_path.is_dir():
        print(f"Error: Project path '{project_path}' does not exist or is not a directory.", file=sys.stderr)
        sys.exit(2)

    findings = analyze_project(project_path)

    if args.format == "json":
        print_json_output(findings)
    else:
        print_text_output(findings)

    # Determine exit code for CI/CD integration
    exit_code = 0
    fail_threshold = SEVERITY_LEVELS[args.fail_on_level.upper()]
    if any(SEVERITY_LEVELS.get(f.severity.upper(), 0) >= fail_threshold for f in findings):
        exit_code = 1
    
    if exit_code != 0:
        print(f"\nAnalysis failed: Found issues at or above '{args.fail_on_level}' severity.", file=sys.stderr)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()