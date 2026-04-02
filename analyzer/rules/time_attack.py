import logging
from typing import List, Dict, Any, Set

from .base import Rule, Finding, Severity

logger = logging.getLogger(__name__)

class TimeAttackRule(Rule):
    """
    Detects choices that use the ledger time (`getTime`) without proper time bounds.

    Rationale:
    A choice that depends on the current time but lacks a deadline can be exercised
    long after it was intended. This can lead to unexpected state changes or economic
    exploits, such as accepting an old offer at a now-favorable price. While ledger time
    is validated, the primary risk is the indefinite validity of a time-sensitive action.
    """

    id = "DAML-T-01"
    name = "Unbounded Time-Sensitive Choice"
    description = "A choice uses `getTime` but does not appear to enforce a time-based constraint (e.g., a deadline)."
    severity = Severity.MEDIUM
    tags = ["time", "security", "business-logic", "race-condition"]

    def check(self, ast: Dict[str, Any]) -> List[Finding]:
        """
        Scans the Daml AST for time-sensitive vulnerabilities.

        Args:
            ast: The abstract syntax tree of the Daml project.

        Returns:
            A list of findings for any detected vulnerabilities.
        """
        findings: List[Finding] = []
        for module_name, module_data in ast.get("modules", {}).items():
            for template in module_data.get("templates", []):
                template_fields = {
                    field["name"] for field in template.get("fields", []) 
                    if self._is_potential_time_field(field)
                }
                
                for choice in template.get("choices", []):
                    # Assuming parser provides a raw string of the choice body for analysis
                    choice_body = choice.get("raw_body", "")

                    if "getTime" in choice_body:
                        choice_params = {
                            param["name"] for param in choice.get("params", [])
                            if self._is_potential_time_field(param)
                        }
                        
                        potential_deadline_fields = template_fields.union(choice_params)

                        if not self._has_time_bound_check(choice_body, potential_deadline_fields):
                            finding = self._create_finding(
                                module_name,
                                template,
                                choice
                            )
                            findings.append(finding)
        return findings

    def _is_potential_time_field(self, field_or_param: Dict[str, str]) -> bool:
        """Heuristically determines if a field is for a time/deadline."""
        field_type = field_or_param.get("type", "").lower()
        field_name = field_or_param.get("name", "").lower()
        
        is_time_type = field_type == "time"
        has_time_name = "time" in field_name or "deadline" in field_name or "expiry" in field_name
        
        return is_time_type or has_time_name

    def _has_time_bound_check(self, choice_body: str, deadline_fields: Set[str]) -> bool:
        """
        Checks if the choice body contains an 'ensure' statement that references
        a potential deadline field. This is a heuristic-based check.
        """
        # Quick check for the presence of an `ensure` clause.
        if "ensure" not in choice_body:
            return False

        # Check for common time comparison operators.
        if "<" not in choice_body and ">" not in choice_body:
            return False

        # Look for a line containing 'ensure', a comparison, and one of the deadline fields.
        lines = choice_body.splitlines()
        for line in lines:
            trimmed_line = line.strip()
            if trimmed_line.startswith("ensure"):
                for field in deadline_fields:
                    if field in trimmed_line:
                        return True
        return False

    def _create_finding(self, module_name: str, template: Dict[str, Any], choice: Dict[str, Any]) -> Finding:
        """Helper to construct a Finding object."""
        template_name = template["name"]
        choice_name = choice["name"]
        location = choice.get("location", {})

        message = (
            f"In template '{template_name}', the choice '{choice_name}' uses `getTime` "
            "without a corresponding `ensure` clause to check against a deadline. "
            "This can allow the choice to be exercised at any point in the future, "
            "potentially leading to exploitation of stale offers or terms."
        )
        recommendation = (
            "Add a `Time` field (e.g., `expiryTime`) to the template or choice "
            "and enforce it within an `ensure` block. For example: "
            "`currentTime <- getTime; ensure currentTime <= expiryTime`."
        )
        
        file_path = f"daml/{module_name.replace('.', '/')}.daml"

        return Finding(
            rule_id=self.id,
            name=self.name,
            description=self.description,
            severity=self.severity,
            location={
                "file_path": file_path,
                "start_line": location.get("start_line"),
                "end_line": location.get("end_line"),
            },
            message=message,
            recommendation=recommendation
        )