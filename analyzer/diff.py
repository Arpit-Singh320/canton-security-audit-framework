# Copyright (c) 2024 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import argparse
import sys
from typing import List, Dict, Any, Tuple, Set

# ANSI color codes for terminal output
class Colors:
    """A collection of ANSI escape codes for colorizing terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLORS = {
    "CRITICAL": Colors.FAIL,
    "HIGH": Colors.FAIL,
    "MEDIUM": Colors.WARNING,
    "LOW": Colors.OKCYAN,
    "INFO": Colors.OKBLUE,
}

Finding = Dict[str, Any]
FindingKey = Tuple[str, str, int, str]

def load_report(filepath: str) -> List[Finding]:
    """
    Loads and validates a JSON audit report from the given file path.
    Exits the program if the file is not found, is not valid JSON,
    or does not conform to the expected finding structure.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Report must be a JSON list of findings.")
        # Basic validation of each finding's structure
        for finding in data:
            if not all(k in finding for k in ["rule_id", "message", "severity", "location"]):
                raise ValueError(f"Invalid finding format: {finding}")
            if not all(k in finding["location"] for k in ["file", "line"]):
                 raise ValueError(f"Invalid location format in finding: {finding}")
        return data
    except FileNotFoundError:
        print(f"{Colors.FAIL}Error: File not found at '{filepath}'{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{Colors.FAIL}Error: Invalid JSON in file '{filepath}'{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"{Colors.FAIL}Error reading report '{filepath}': {e}{Colors.ENDC}", file=sys.stderr)
        sys.exit(1)

def finding_to_key(finding: Finding) -> FindingKey:
    """
    Creates a unique, hashable key for a finding based on its core properties.
    This allows for efficient comparison of findings between reports.
    """
    location = finding['location']
    return (
        finding['rule_id'],
        location['file'],
        location.get('line', 0), # Use 0 if line number is missing
        finding['message'].strip()
    )

def compare_reports(old_findings: List[Finding], new_findings: List[Finding]) -> Dict[str, List[Finding]]:
    """
    Compares two lists of findings and categorizes them into 'fixed', 'added',
    and 'existing' based on their unique keys.
    """
    old_map = {finding_to_key(f): f for f in old_findings}
    new_map = {finding_to_key(f): f for f in new_findings}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    fixed_keys = old_keys - new_keys
    added_keys = new_keys - old_keys
    existing_keys = old_keys & new_keys

    # Sort results for consistent output
    key_func = lambda f: (f['location']['file'], f['location'].get('line', 0))
    return {
        "fixed": sorted([old_map[k] for k in fixed_keys], key=key_func),
        "added": sorted([new_map[k] for k in added_keys], key=key_func),
        "existing": sorted([new_map[k] for k in existing_keys], key=key_func),
    }

def print_findings_list(title: str, findings: List[Finding], color: str):
    """Prints a formatted and colorized list of findings to the console."""
    if not findings:
        return

    print(f"\n{color}{Colors.BOLD}{title} ({len(findings)}){Colors.ENDC}")
    print(f"{color}{'-' * (len(title) + 4)}{Colors.ENDC}")

    for f in findings:
        sev_color = SEVERITY_COLORS.get(f['severity'].upper(), Colors.ENDC)
        loc = f['location']
        print(
            f"  [{sev_color}{f['severity']:<8}{color}] "
            f"{Colors.BOLD}{f['rule_id']}{Colors.ENDC}{color} at "
            f"{loc['file']}:{loc.get('line', '?')}{Colors.ENDC}"
        )
        print(f"  {color}         -> {f['message']}{Colors.ENDC}")

def print_summary(diff_results: Dict[str, List[Finding]]):
    """Prints a high-level summary of the comparison results."""
    num_added = len(diff_results["added"])
    num_fixed = len(diff_results["fixed"])
    num_existing = len(diff_results["existing"])
    total_new_report = num_added + num_existing

    print(f"{Colors.HEADER}{Colors.BOLD}=== Audit Report Diff Summary ==={Colors.ENDC}")
    print(f"  Existing Findings: {num_existing}")
    print(f"  {Colors.OKGREEN}Fixed Findings:    {num_fixed}{Colors.ENDC}")
    print(f"  {Colors.FAIL}New Findings:      {num_added}{Colors.ENDC}")
    print("-" * 33)
    print(f"  Total Findings in New Report: {total_new_report}")

    print_findings_list("New Findings", diff_results["added"], Colors.FAIL)
    print_findings_list("Fixed Findings", diff_results["fixed"], Colors.OKGREEN)
    print_findings_list("Existing Findings", diff_results["existing"], Colors.WARNING)

def main():
    """Main entry point for the command-line diff tool."""
    parser = argparse.ArgumentParser(
        description="Compare two Canton Security Audit Framework reports to identify new, fixed, and existing vulnerabilities.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "old_report",
        help="Path to the baseline/old JSON audit report (e.g., from the main branch)."
    )
    parser.add_argument(
        "new_report",
        help="Path to the new JSON audit report (e.g., from a feature branch)."
    )
    parser.add_argument(
        "--fail-on-new",
        metavar="SEVERITY",
        choices=SEVERITY_ORDER.keys(),
        default="HIGH",
        help=(
            "Exit with a non-zero status code if new findings with this severity or higher are found.\n"
            "Choices: CRITICAL, HIGH, MEDIUM, LOW, INFO.\n"
            "Default: HIGH."
        )
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colorized output, suitable for logging to a file."
    )

    args = parser.parse_args()

    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith("__"):
                setattr(Colors, attr, "")

    old_findings = load_report(args.old_report)
    new_findings = load_report(args.new_report)

    diff = compare_reports(old_findings, new_findings)
    print_summary(diff)

    # Check for failure condition, useful for CI/CD pipelines
    fail_threshold = SEVERITY_ORDER[args.fail_on_new.upper()]
    should_fail = any(
        SEVERITY_ORDER.get(finding["severity"].upper(), -1) >= fail_threshold
        for finding in diff["added"]
    )

    if should_fail:
        print(f"\n{Colors.FAIL}{Colors.BOLD}CI Check FAILED: New findings with severity '{args.fail_on_new}' or higher were introduced.{Colors.ENDC}")
        sys.exit(1)
    else:
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}CI Check PASSED: No new findings at or above '{args.fail_on_new}' severity were introduced.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()