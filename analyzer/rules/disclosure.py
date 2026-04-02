"""
Rule: Unintended Observer Disclosure

Description:
Detects scenarios where parties might gain unintended access to contract data by being added as an observer,
either directly or indirectly. This includes:
1.  Explicit Observers: A party is added as an observer but is not a signatory. This can be intentional
    but warrants review.
2.  Implicit Observers (Create): A choice controller becomes an observer of a contract created within
    that choice. If the controller is not a signatory of the new contract, it may be an unintended
    disclosure of the new contract's data.
3.  Implicit Observers (Fetch): A choice controller gains visibility of a contract that is 'fetched'
    within the choice. If the controller is not already a stakeholder (signatory or observer) of the
    fetched contract type, this could be a disclosure vulnerability.

Example of a vulnerability (Implicit via Fetch):
template SecretData
  with
    owner: Party
    data: Text
  where
    signatory owner

template PublicPortal
  with
    operator: Party
    secretCid: ContractId SecretData
  where
    signatory operator
    choice ViewSecretForUser : ()
      with
        user: Party -- Any party can be passed in here
      controller user
      do
        -- VULNERABILITY: 'user' is the controller and is not a stakeholder of
        -- SecretData, but this fetch discloses the entire contract to them.
        fetch secretCid
        return ()
"""

from .base import Rule, Issue, Severity
from ..parser import DamlFile, Template, Choice, Location

class DisclosureRule(Rule):
    """
    Analyzes Daml code for potential unintended observer disclosures.
    """
    def __init__(self):
        super().__init__(
            "DISC-001",
            "Unintended Observer Disclosure",
            Severity.MEDIUM
        )

    def analyze(self, daml_file: DamlFile) -> list[Issue]:
        """Runs the analysis on a parsed Daml file."""
        issues = []
        for template in daml_file.get_templates():
            issues.extend(self._check_explicit_observers(template))
            for choice in template.get_choices():
                issues.extend(self._check_implicit_disclosure_in_choice(daml_file, template, choice))
        return issues

    def _get_party_identifiers(self, expression_list: list[str]) -> set[str]:
        """
        Extracts simple party identifiers from expression strings.
        This is a simplification; it won't resolve complex expressions but handles
        common patterns like `owner`, `[p1, p2]`, and `(signatory self) ++ observers`.
        """
        parties = set()
        for expr in expression_list:
            # Simple heuristic to extract identifiers by cleaning and tokenizing
            cleaned_expr = expr.replace('(', ' ').replace(')', ' ').replace('[', ' ').replace(']', ' ').replace(',', ' ')
            tokens = [token.strip() for token in cleaned_expr.split() if token.strip() and token.strip() not in ["signatory", "observer"]]
            parties.update(tokens)
        return parties

    def _check_explicit_observers(self, template: Template) -> list[Issue]:
        """
        Checks if a template explicitly names observers who are not signatories.
        This is not always a bug but requires careful review.
        """
        issues = []
        signatory_exprs = template.signatories
        observer_exprs = template.observers

        if not observer_exprs:
            return []

        signatory_parties = self._get_party_identifiers(signatory_exprs)
        observer_parties = self._get_party_identifiers(observer_exprs)

        # In Daml, 'signatory self' means the parties listed in the signatory clause.
        # So we can effectively model signatories as all template fields if 'self' is used.
        if 'self' in signatory_parties:
            signatory_parties.remove('self')
            signatory_parties.update(template.fields.keys())

        # An observer list might reference 'signatory self', which is safe.
        if 'self' in observer_parties:
            observer_parties.remove('self')

        # Find observers that are not also signatories.
        potential_leaks = observer_parties - signatory_parties
        
        # Filter out identifiers that are known fields of the template, as they are likely
        # intended to be observers (e.g., observer owner).
        potential_leaks = {p for p in potential_leaks if p not in template.fields}

        if potential_leaks:
            issues.append(
                self.make_issue(
                    template.location,
                    f"Template '{template.name}' has observers who may not be signatories: {sorted(list(potential_leaks))}. "
                    "Review if these parties should have access to contract data."
                )
            )
        return issues

    def _check_implicit_disclosure_in_choice(self, daml_file: DamlFile, template: Template, choice: Choice) -> list[Issue]:
        """
        Checks for disclosures caused by `create` and `fetch` within a choice, where the
        choice controller gains visibility.
        """
        issues = []
        controller_parties = self._get_party_identifiers(choice.controllers)

        for action in choice.body_actions:
            if action['type'] == 'create':
                issues.extend(self._analyze_create_action(daml_file, template, choice, action, controller_parties))
            elif action['type'] == 'fetch':
                issues.extend(self._analyze_fetch_action(daml_file, template, choice, action, controller_parties))

        return issues

    def _analyze_create_action(self, daml_file: DamlFile, current_template: Template, choice: Choice, action: dict, controller_parties: set) -> list[Issue]:
        """Analyzes a `create` action for disclosure."""
        created_template_name = action.get('template')
        created_template = daml_file.get_template_by_name(created_template_name)
        if not created_template:
            return []
        
        created_signatories = self._get_party_identifiers(created_template.signatories)
        if 'self' in created_signatories:
            created_signatories.remove('self')
            created_signatories.update(created_template.fields.keys())

        # A choice controller becomes an observer of the created contract.
        # If the controller is not also a signatory, this could be an unintended disclosure.
        leaking_controllers = controller_parties - created_signatories
        leaking_controllers = {p for p in leaking_controllers if p not in current_template.fields}
        
        if not leaking_controllers:
            return []

        choice_params = set(choice.params.keys())
        high_risk_controllers = leaking_controllers.intersection(choice_params)

        if high_risk_controllers:
            return [self.make_issue(
                action.get('location', choice.location),
                f"In choice '{choice.name}', controller '{list(high_risk_controllers)[0]}' (from a choice argument) becomes an "
                f"observer of a newly created '{created_template_name}' contract without being a signatory. "
                "This could allow an arbitrary party to view the new contract.",
                severity=Severity.HIGH
            )]
        
        return [self.make_issue(
            action.get('location', choice.location),
            f"In choice '{choice.name}', controller(s) {sorted(list(leaking_controllers))} become observers "
            f"of a newly created '{created_template_name}' contract without being signatories."
        )]
    
    def _analyze_fetch_action(self, daml_file: DamlFile, current_template: Template, choice: Choice, action: dict, controller_parties: set) -> list[Issue]:
        """Analyzes a `fetch` action for disclosure."""
        fetched_template_name = action.get('template')
        if not fetched_template_name:
            return []
            
        fetched_template = daml_file.get_template_by_name(fetched_template_name)
        if not fetched_template:
            return []

        stakeholders = self._get_party_identifiers(fetched_template.signatories)
        stakeholders.update(self._get_party_identifiers(fetched_template.observers))
        if 'self' in stakeholders:
            stakeholders.remove('self')
            stakeholders.update(fetched_template.fields.keys())

        # If a controller fetches a contract they are not a stakeholder of, it's a disclosure.
        leaking_controllers = controller_parties - stakeholders
        leaking_controllers = {p for p in leaking_controllers if p not in current_template.fields}

        if not leaking_controllers:
            return []

        choice_params = set(choice.params.keys())
        high_risk_controllers = leaking_controllers.intersection(choice_params)

        if high_risk_controllers:
            return [self.make_issue(
                action.get('location', choice.location),
                f"In choice '{choice.name}', controller '{list(high_risk_controllers)[0]}' (from a choice argument) "
                f"fetches a '{fetched_template_name}' contract, gaining access. Ensure this is intended, as any party "
                "could be passed to the choice.",
                severity=Severity.HIGH
            )]
        
        return [self.make_issue(
            action.get('location', choice.location),
            f"In choice '{choice.name}', controller(s) {sorted(list(leaking_controllers))} fetch a "
            f"'{fetched_template_name}' contract but are not defined as stakeholders (signatory or observer) "
            "on that template."
        )]