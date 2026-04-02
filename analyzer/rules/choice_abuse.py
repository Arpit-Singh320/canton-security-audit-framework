"""
Rule: Unbounded Recursive Choice
ID: DAML-R02
Severity: High/Medium

Description:
This rule detects choices that recursively create a new instance of their own template.
If this recursion is not properly bounded by a termination condition, it can be
exploited to create an infinite number of contracts, leading to performance
degradation or denial-of-service on the ledger.

The rule distinguishes between:
1. Unconditional Recursion (High Severity): A 'create' of the same template
   exists in the main body of the choice, not guarded by an 'if' statement.
   This is very likely a vulnerability.
2. Conditional Recursion (Medium Severity): A 'create' of the same template
   is found inside an 'if' block. This is a common pattern for state evolution,
   but it requires manual verification to ensure the condition will eventually
   terminate the recursion (e.g., a counter that decrements to zero).

Example of a vulnerable contract (Unconditional):
template Unbounded
  with
    owner: Party
  where
    signatory owner
    choice Evolve: ContractId Unbounded
      controller owner
      do
        create this

Example of a potentially safe contract (Conditional):
template Bounded
  with
    owner: Party
    counter: Int
  where
    signatory owner
    choice Evolve: ContractId Bounded
      controller owner
      do
        ensure (this.counter > 0)
        create this with counter = this.counter - 1
"""

from typing import List, Optional, Tuple

# These imports are hypothetical, based on the project's parser and base rule definitions.
from ..parser.daml_ast import (
    TemplateNode,
    ChoiceNode,
    CreateNode,
    IfNode,
    StatementNode,
)
from .base_rule import Rule, Finding, Severity


class ChoiceAbuseUnboundedRecursionRule(Rule):
    """
    Identifies choices that recursively create a contract of the same template.
    """

    def get_id(self) -> str:
        return "DAML-R02"

    def get_description(self) -> str:
        return "Detects choices that may be exercised recursively without a clear termination condition."

    def run(self, ast) -> List[Finding]:
        """
        Runs the check on the given Abstract Syntax Tree.
        """
        findings: List[Finding] = []
        for template in ast.get_templates():
            findings.extend(self._check_template(template))
        return findings

    def _check_template(self, template: TemplateNode) -> List[Finding]:
        """
        Checks a single template for recursive choices.
        """
        template_findings: List[Finding] = []
        for choice in template.choices:
            result = self._find_recursive_create(choice.body, template.name)
            if result:
                create_node, is_conditional = result
                if not is_conditional:
                    # Unconditional recursion is a high severity finding
                    message = (
                        f"Choice '{choice.name}' in template '{template.name}' unconditionally "
                        f"creates a new instance of the same template. This can lead to an "
                        f"unbounded recursion, potentially causing denial-of-service or "
                        f"excessive ledger growth. Ensure a proper termination condition is in place, "
                        f"for example, using an 'ensure' clause with a decrementing counter."
                    )
                    template_findings.append(
                        Finding(
                            rule_id=self.get_id(),
                            message=message,
                            severity=Severity.HIGH,
                            location=create_node.location,
                        )
                    )
                else:
                    # Conditional recursion is a medium severity finding, requires manual review
                    message = (
                        f"Choice '{choice.name}' in template '{template.name}' conditionally "
                        f"creates a new instance of the same template. Please manually verify "
                        f"that the condition guarantees termination to prevent unbounded recursion. "
                        f"For example, ensure a counter is always decreasing and checked."
                    )
                    template_findings.append(
                        Finding(
                            rule_id=self.get_id(),
                            message=message,
                            severity=Severity.MEDIUM,
                            location=create_node.location,
                        )
                    )
        return template_findings

    def _find_recursive_create(
        self,
        statements: List[StatementNode],
        template_name: str,
        is_conditional: bool = False,
    ) -> Optional[Tuple[CreateNode, bool]]:
        """
        Recursively searches a list of statements for a 'create' of the given template_name.

        Returns a tuple (CreateNode, is_conditional) if found, otherwise None.
        The 'is_conditional' flag is threaded through the recursion to track if the
        create statement was found inside any conditional block.
        """
        for stmt in statements:
            if isinstance(stmt, CreateNode) and stmt.template_name == template_name:
                return (stmt, is_conditional)

            if isinstance(stmt, IfNode):
                # Any 'create' found inside an 'if' block is considered conditional.
                # We search both branches.
                then_result = self._find_recursive_create(
                    stmt.then_branch, template_name, is_conditional=True
                )
                if then_result:
                    return then_result

                if stmt.else_branch:
                    else_result = self._find_recursive_create(
                        stmt.else_branch, template_name, is_conditional=True
                    )
                    if else_result:
                        return else_result

        return None