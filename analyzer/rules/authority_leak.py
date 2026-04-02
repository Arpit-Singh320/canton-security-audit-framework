# Copyright (c) 2024 Digital Asset (Canton) GmbH and/or its affiliates. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import os
from typing import List, Dict, Any, Set

# This file defines a static analysis rule for detecting potential authority leaks
# in Daml smart contracts. An authority leak occurs when a choice allows a party
# to create a contract that confers signatory rights upon another party without
# that other party's explicit consent within the choice's authorization context.
#
# The specific pattern we detect is:
# A `create` statement inside a choice, where:
# 1. The new contract has a signatory `S`.
# 2. The party for `S` is provided via a choice parameter `p`.
# 3. `p` is NOT listed as a controller of the choice.
#
# This allows the choice's controller `C` to create a contract obligating `p`
# to be a signatory, which `p` never authorized in the context of this choice.
# While the Canton ledger's transaction authorization rules would prevent this
# transaction from succeeding without `p`'s signature, it represents a flaw
# in the smart contract logic that should be caught by static analysis.

class Finding:
    """Represents a single vulnerability or issue found by a rule."""
    def __init__(self, rule_id: str, file_path: str, line: int, message: str):
        self.rule_id = rule_id
        self.file_path = os.path.normpath(file_path)
        self.line = line
        self.message = message

    def __repr__(self) -> str:
        return f"{self.file_path}:{self.line}: [{self.rule_id}] {self.message}"

class AuthorityLeakRule:
    """
    Detects when a choice creates a contract where a signatory is a party
    provided as a choice argument, but that party is not a controller of the choice.
    """
    RULE_ID = "DA001"
    DESCRIPTION = "Potential Authority Leak: A choice controller grants signatory rights to a non-controller party."

    def analyze(self, ast: Dict[str, Any]) -> List[Finding]:
        """
        Analyzes the given Daml project AST for authority leaks.

        Args:
            ast: The abstract syntax tree of the Daml project.

        Returns:
            A list of Finding objects representing detected vulnerabilities.
        """
        findings: List[Finding] = []
        templates_map = self._get_templates_map(ast)

        for module in ast.get("modules", []):
            for template in module.get("templates", []):
                for choice in template.get("choices", []):
                    findings.extend(self._check_choice(module, choice, templates_map))
        return findings

    def _get_templates_map(self, ast: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a flat map of template names to their definitions for easy lookup."""
        templates_map: Dict[str, Any] = {}
        for module in ast.get("modules", []):
            module_name = module.get("name")
            for template in module.get("templates", []):
                template_name = template.get("name")
                if not template_name:
                    continue
                # Store by both simple and fully qualified name if possible
                templates_map[template_name] = template
                if module_name:
                    qualified_name = f"{module_name}.{template_name}"
                    templates_map[qualified_name] = template
        return templates_map

    def _check_choice(self, module: Dict[str, Any], choice: Dict[str, Any], templates_map: Dict[str, Any]) -> List[Finding]:
        """Checks a single choice for authority leak vulnerabilities."""
        findings: List[Finding] = []
        
        # The set of authorizing parties are the controllers of the choice.
        # These are treated as symbolic variable names for static analysis.
        controller_vars: Set[str] = set(choice.get("controllers", []))

        # The set of variables that are choice parameters.
        choice_param_vars: Set[str] = set(choice.get("params", {}).keys())

        for stmt in choice.get("body", []):
            if stmt.get("type") == "create":
                created_template_name = stmt.get("template")
                if not created_template_name:
                    continue

                created_template_def = templates_map.get(created_template_name)
                if not created_template_def:
                    # Can't find the template definition, so we can't analyze its signatories.
                    continue

                signatory_fields: List[str] = created_template_def.get("signatories", [])
                create_args: Dict[str, str] = stmt.get("args", {})

                for sig_field in signatory_fields:
                    # Find which variable is being used to populate this signatory field.
                    source_var = create_args.get(sig_field)
                    
                    if not source_var:
                        # This signatory field might be populated by a complex expression
                        # (e.g., from `this` or a `let` binding). A more advanced analyzer
                        # would use data-flow analysis. For this rule, we focus on the
                        # most common vulnerability pattern: direct assignment from a choice param.
                        continue

                    # THE VULNERABILITY CONDITION:
                    # The source of the signatory is a choice parameter, AND that parameter
                    # is NOT also a controller of the choice.
                    if source_var in choice_param_vars and source_var not in controller_vars:
                        message = (
                            f"In choice '{choice['name']}', a contract of template '{created_template_name}' is created. "
                            f"Its signatory field '{sig_field}' is populated by the choice parameter '{source_var}'. "
                            f"However, '{source_var}' is not a controller of the choice. "
                            f"This allows a controller to grant signatory rights to '{source_var}' without their consent."
                        )
                        findings.append(Finding(
                            rule_id=self.RULE_ID,
                            file_path=module.get("path", "unknown_file"),
                            line=stmt.get("line", choice.get("line")),
                            message=message
                        ))
        return findings

# Example usage for standalone testing of this rule.
# In a real application, this would be orchestrated by a main runner.
if __name__ == '__main__':
    # This is a mock AST representing a vulnerable Daml contract.
    # The structure is a simplified representation of what a real Daml parser might produce.
    mock_ast = {
        "modules": [
            {
                "name": "VulnerableModule",
                "path": "daml/Vulnerable.daml",
                "templates": [
                    {
                        "name": "MasterAgreement",
                        "fields": {"operator": "Party", "counterparty": "Party"},
                        "signatories": ["operator"],
                        "choices": [
                            {
                                "name": "DelegateAdminRole_VULNERABLE",
                                "line": 15,
                                "params": {"newAdmin": "Party"},
                                "controllers": ["operator"],
                                "body": [
                                    {
                                        "type": "create",
                                        "line": 18,
                                        "template": "AdminRole",
                                        "args": {"user": "newAdmin", "granter": "operator"}
                                    }
                                ]
                            },
                             {
                                "name": "DelegateAdminRole_SAFE",
                                "line": 25,
                                "params": {"newAdmin": "Party"},
                                "controllers": ["operator", "newAdmin"], # Correct: newAdmin must co-sign.
                                "body": [
                                    {
                                        "type": "create",
                                        "line": 28,
                                        "template": "AdminRole",
                                        "args": {"user": "newAdmin", "granter": "operator"}
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "name": "AdminRole",
                        "fields": {"user": "Party", "granter": "Party"},
                        "signatories": ["user"],
                        "choices": []
                    }
                ]
            }
        ]
    }

    rule = AuthorityLeakRule()
    findings = rule.analyze(mock_ast)

    print(f"--- Analysis Results for {rule.RULE_ID}: {rule.DESCRIPTION} ---")
    if not findings:
        print("No vulnerabilities found.")
    else:
        for f in findings:
            print(f"\n[FOUND] {f}")
    
    assert len(findings) == 1
    assert findings[0].line == 18
    assert findings[0].rule_id == "DA001"
    print("\nTest finished: Exactly one vulnerability was correctly identified.")
