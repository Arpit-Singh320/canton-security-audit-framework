import re
from typing import List, Dict, NamedTuple, Set, Optional

class Finding(NamedTuple):
    """
    Represents a single vulnerability or issue found by a rule.
    """
    file_path: str
    line_number: int
    rule_id: str
    description: str
    confidence: str  # "High", "Medium", "Low"

class AuthorityLeakRule:
    """
    Identifies Authority Leak vulnerabilities in Daml contracts.
    
    ID: DA001
    Description: This rule detects when a choice allows a controller to perform an action
                 (e.g., creating a contract) that requires the authority of another party
                 who is not a controller of the choice. This often occurs when data from a
                 `fetch` operation is used to populate a signatory field in a `create` statement.

    The improved logic specifically targets cases where a signatory of a new contract is not
    in the controller set of the choice, and traces the signatory's value back to a fetched
    contract, thereby excluding known-safe patterns where the controller is creating contracts
    on their own behalf.
    """
    RULE_ID = "DA001"
    DESCRIPTION = "Potential authority leak: a choice action uses the authority of a non-controller party."

    # Regex to find `template TemplateName ... where` blocks. Captures name and body.
    TEMPLATE_RE = re.compile(
        r"^\s*template\s+(\w+)\s+with.*?^\s*where\n(.*?)(?=^\s*template|\Z)",
        re.DOTALL | re.MULTILINE
    )

    # Find `signatory ...` within the `where` block of a template
    SIGNATORY_RE = re.compile(r"signatory\s+([()\w\s,.]+)")

    # Find `choice ChoiceName ... controller ... do` blocks
    CHOICE_RE = re.compile(
        r"^\s*choice\s+.*?controller\s+([()\w\s,.]+)\s+do(.*?)(?=^\s*choice|^\s*template)",
        re.DOTALL | re.MULTILINE
    )
    
    # Find `choice Name...` to extract the name
    CHOICE_NAME_RE = re.compile(r"^\s*choice\s+(\w+)", re.MULTILINE)

    # Find `create TemplateName with ...` statements
    CREATE_RE = re.compile(r"create\s+(\w+)\s+with\s+(.*)")

    # Find `var <- fetch cid` statements
    FETCH_RE = re.compile(r"^\s*([\w_]+)\s*<-\s*fetch\s+", re.MULTILINE)

    def analyze(self, file_path: str, content: str) -> List[Finding]:
        """
        Analyzes the given Daml file content for authority leaks.
        """
        findings = []
        templates_signatories = self._get_templates_and_signatories(content)

        for template_match in self.TEMPLATE_RE.finditer(content):
            template_body = template_match.group(2)
            
            for choice_match in self.CHOICE_RE.finditer(template_body):
                controllers_str = choice_match.group(1)
                choice_body = choice_match.group(2)
                
                choice_name_match = self.CHOICE_NAME_RE.search(choice_match.group(0))
                choice_name = choice_name_match.group(1) if choice_name_match else "UnnamedChoice"

                controllers = self._parse_party_list(controllers_str)
                fetched_vars = {m.group(1) for m in self.FETCH_RE.finditer(choice_body)}

                for create_match in self.CREATE_RE.finditer(choice_body):
                    created_template = create_match.group(1)
                    create_args_str = create_match.group(2)
                    
                    if created_template not in templates_signatories:
                        continue

                    signatory_fields = templates_signatories[created_template]
                    create_args = self._parse_with_block(create_args_str)

                    for sig_field in signatory_fields:
                        signatory_value = create_args.get(sig_field)
                        if not signatory_value:
                            continue

                        # Core Logic: If the party providing signatory authority is not a 
                        # controller of the choice, it's a potential leak.
                        if signatory_value not in controllers:
                            confidence, reason = self._assess_leak_confidence(signatory_value, fetched_vars)

                            if confidence:
                                line_number = self._get_line_number(content, choice_match.start(2) + create_match.start())
                                findings.append(Finding(
                                    file_path=file_path,
                                    line_number=line_number,
                                    rule_id=self.RULE_ID,
                                    description=(
                                        f"In choice '{choice_name}', contract '{created_template}' is created with "
                                        f"signatory '{signatory_value}' which resolves to a party that is not a choice controller. "
                                        f"{reason}"
                                    ),
                                    confidence=confidence
                                ))
        return findings

    def _assess_leak_confidence(self, signatory_value: str, fetched_vars: Set[str]) -> (Optional[str], str):
        """
        Determines the confidence level of a potential authority leak.
        - High: The signatory value comes directly from a fetched contract.
        - Medium: The signatory value is a variable, but not from a known safe source (like a controller).
        """
        if '.' in signatory_value:
            base_var, _ = signatory_value.split('.', 1)
            if base_var in fetched_vars:
                return "High", "The signatory's authority is derived from a fetched contract."

        # Exclude literals (e.g., hardcoded Party literals, though rare)
        if signatory_value.startswith('"') or signatory_value.isdigit():
            return None, ""
            
        return "Medium", "The signatory is a variable whose authority source could not be verified as safe."

    def _get_templates_and_signatories(self, content: str) -> Dict[str, Set[str]]:
        """Parses the entire file to map template names to their signatory fields."""
        results = {}
        for template_match in self.TEMPLATE_RE.finditer(content):
            template_name = template_match.group(1).strip()
            template_body = template_match.group(2)
            sig_match = self.SIGNATORY_RE.search(template_body)
            if sig_match:
                results[template_name] = self._parse_party_list(sig_match.group(1))
        return results
    
    def _parse_party_list(self, party_str: str) -> Set[str]:
        """Parses a comma-separated list of parties, handling parentheses."""
        sanitized_str = party_str.replace('\n', ' ').strip()
        if sanitized_str.startswith('(') and sanitized_str.endswith(')'):
            sanitized_str = sanitized_str[1:-1]
        
        return {p.strip() for p in sanitized_str.split(',') if p.strip()}

    def _parse_with_block(self, with_str: str) -> Dict[str, str]:
        """A simple parser for `field1 = value1, field2 = value2`."""
        args = {}
        # This regex handles `key = value` pairs, ignoring commas within parentheses.
        # This is a simplification; a full parser would be needed for complex cases.
        arg_re = re.compile(r"(\w+)\s*=\s*([\w.'\"_]+)")
        for match in arg_re.finditer(with_str):
            args[match.group(1)] = match.group(2)
        return args

    def _get_line_number(self, content: str, char_index: int) -> int:
        """Calculates the 1-based line number for a given character index."""
        return content.count('\n', 0, char_index) + 1