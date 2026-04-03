import pytest
from collections import namedtuple

# Assume the analyzer returns findings in a structured way.
# A real implementation might be a more complex class.
Finding = namedtuple('Finding', ['rule_id', 'message', 'location'])

# Assume these functions exist in the analyzer. The tests will validate their logic
# against different Daml contract structures, which we represent as dictionaries.
from analyzer.rules import (
    check_improper_signatory_subset,
    check_time_dependency,
    check_unsafe_state_update,
    check_observer_disclosure_risk
)

# --- Test Fixtures for Parsed Daml Data Structures ---

@pytest.fixture
def parsed_daml_authority_leak():
    """ A parsed Daml structure representing a contract where a choice controller
        is a proper subset of the signatories, allowing one party to act on behalf
        of another without their explicit choice participation.
    """
    return {
        "module_name": "AuthorityLeak",
        "templates": [
            {
                "name": "SharedAccount",
                "line_num": 3,
                "signatories": ["owner1", "owner2"],
                "observers": [],
                "choices": [
                    {
                        "name": "Withdraw",
                        "line_num": 9,
                        "controllers": ["owner1"],  # Vulnerability: owner1 can act alone
                        "body": "do create Withdrawal with ..",
                    }
                ],
            }
        ],
    }

@pytest.fixture
def parsed_daml_authority_safe():
    """ A parsed Daml structure with correct authority handling.
        - Choice controller matches all signatories.
        - A proposal pattern where the controller is a stakeholder, but not the full signatory list.
    """
    return {
        "module_name": "AuthoritySafe",
        "templates": [
            {
                "name": "SharedAccount",
                "line_num": 3,
                "signatories": ["owner1", "owner2"],
                "observers": [],
                "choices": [
                    {
                        "name": "Withdraw",
                        "line_num": 9,
                        "controllers": ["owner1", "owner2"], # Safe: requires both signatories
                        "body": "do create Withdrawal with ..",
                    }
                ],
            },
            {
                "name": "TradeProposal",
                "line_num": 18,
                "signatories": ["proposer"],
                "observers": ["counterparty"],
                "choices": [
                    {
                        "name": "Accept",
                        "line_num": 24,
                        "controllers": ["counterparty"], # Safe: common proposal/accept pattern
                        "body": "do create Trade with ..",
                    }
                ]
            }
        ],
    }

@pytest.fixture
def parsed_daml_time_dependent():
    """ A parsed Daml structure where a choice's logic depends on `getTime`.
        This is risky because the submitter of the transaction can influence the time.
    """
    return {
        "module_name": "TimeDependent",
        "templates": [
            {
                "name": "TimeLock",
                "line_num": 3,
                "signatories": ["operator"],
                "observers": [],
                "choices": [
                    {
                        "name": "Unlock",
                        "line_num": 8,
                        "controllers": ["operator"],
                        "body": "do\n  now <- getTime\n  assert (now >= self.unlockTime)",
                    }
                ],
            }
        ],
    }

@pytest.fixture
def parsed_daml_time_safe():
    """ A parsed Daml structure where time is handled more safely, for example,
        by being passed in as an argument to the choice.
    """
    return {
        "module_name": "TimeSafe",
        "templates": [
            {
                "name": "TimeLock",
                "line_num": 3,
                "signatories": ["operator"],
                "observers": [],
                "choices": [
                    {
                        "name": "Unlock",
                        "line_num": 8,
                        "controllers": ["operator"],
                        "params": ["currentTime: Time"],
                        # The body doesn't call getTime directly.
                        "body": "do\n  assert (currentTime >= self.unlockTime)",
                    }
                ],
            }
        ],
    }

@pytest.fixture
def parsed_daml_unsafe_update():
    """ A parsed Daml structure representing a risky state update.
        A 'migrate' or 'update' choice archives the old state and creates a new one
        without ensuring critical fields are preserved.
    """
    return {
        "module_name": "UnsafeUpdate",
        "templates": [
            {
                "name": "Asset",
                "line_num": 3,
                "signatories": ["owner"],
                "observers": ["issuer"],
                "choices": [
                    {
                        "name": "UpdateDescription",
                        "line_num": 9,
                        "controllers": ["issuer"],
                        "body": "do\n  archive self\n  create self with description = newDescription",
                    }
                ],
            }
        ],
    }

@pytest.fixture
def parsed_daml_safe_update():
    """ A parsed Daml structure representing a safe state update.
        The `ensure` block is used to constrain the changes made during an update.
    """
    return {
        "module_name": "SafeUpdate",
        "templates": [
            {
                "name": "Asset",
                "line_num": 3,
                "signatories": ["owner"],
                "observers": ["issuer"],
                "choices": [
                    {
                        "name": "UpdateDescription",
                        "line_num": 9,
                        "controllers": ["issuer"],
                        "body": "do\n  ensure (self.owner == newAsset.owner)\n  archive self\n  create newAsset",
                    }
                ],
            }
        ],
    }

@pytest.fixture
def parsed_daml_disclosure_risk():
    """ A parsed Daml structure with a potential data disclosure risk.
        A sensitive field is exposed to an observer who may not be entitled to see it.
    """
    return {
        "module_name": "DisclosureRisk",
        "templates": [
            {
                "name": "EmployeeData",
                "line_num": 3,
                "fields": ["employee: Party", "manager: Party", "salary: Decimal", "ssn: Text"],
                "signatories": ["employee", "manager"],
                "observers": ["auditor"], # Auditor can see ssn
            }
        ],
    }

@pytest.fixture
def parsed_daml_disclosure_safe():
    """ A parsed Daml structure using a safe data segregation pattern.
        Sensitive data is in a separate contract, referenced by ContractId,
        preventing observers of the main contract from seeing it.
    """
    return {
        "module_name": "DisclosureSafe",
        "templates": [
            {
                "name": "EmployeeRole",
                "line_num": 3,
                "fields": ["employee: Party", "manager: Party", "sensitiveDataCid: ContractId EmployeeSensitiveData"],
                "signatories": ["employee", "manager"],
                "observers": ["auditor"], # Auditor cannot see data in the CID
            },
            {
                "name": "EmployeeSensitiveData",
                "line_num": 12,
                "fields": ["employee: Party", "salary: Decimal", "ssn: Text"],
                "signatories": ["employee"], # Only the employee is signatory
                "observers": [],
            }
        ],
    }


# --- Test Suites ---

class TestAuthorityRules:
    """ Tests for rules related to signatories, observers, and controllers. """

    def test_detects_improper_signatory_subset(self, parsed_daml_authority_leak):
        """ Verifies that a choice controlled by a proper subset of signatories is flagged. """
        findings = check_improper_signatory_subset(parsed_daml_authority_leak)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "AUTH-001"
        assert "is a proper subset of signatories" in finding.message
        assert finding.location == "AuthorityLeak:SharedAccount:Withdraw (line 9)"

    def test_ignores_safe_authority_patterns(self, parsed_daml_authority_safe):
        """ Verifies that standard, safe authority patterns do not trigger a finding. """
        findings = check_improper_signatory_subset(parsed_daml_authority_safe)
        assert len(findings) == 0


class TestTemporalRules:
    """ Tests for rules related to time-dependent logic. """

    def test_detects_get_time_in_choice(self, parsed_daml_time_dependent):
        """ Verifies that direct usage of `getTime` inside a choice body is flagged. """
        findings = check_time_dependency(parsed_daml_time_dependent)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "TIME-001"
        assert "uses `getTime`" in finding.message
        assert finding.location == "TimeDependent:TimeLock:Unlock (line 8)"

    def test_ignores_safe_time_handling(self, parsed_daml_time_safe):
        """ Verifies that passing time as a parameter is not flagged. """
        findings = check_time_dependency(parsed_daml_time_safe)
        assert len(findings) == 0


class TestStateUpdateRules:
    """ Tests for rules related to unsafe contract state transitions. """

    def test_detects_unguarded_archive_and_create(self, parsed_daml_unsafe_update):
        """ Verifies that an 'archive-then-create' pattern without an 'ensure' check is flagged. """
        findings = check_unsafe_state_update(parsed_daml_unsafe_update)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == "STATE-001"
        assert "upgrades state without an `ensure`" in finding.message
        assert finding.location == "UnsafeUpdate:Asset:UpdateDescription (line 9)"

    def test_ignores_guarded_state_updates(self, parsed_daml_safe_update):
        """ Verifies that a state upgrade guarded by an 'ensure' block is not flagged. """
        findings = check_unsafe_state_update(parsed_daml_safe_update)
        assert len(findings) == 0


class TestDisclosureRules:
    """ Tests for rules related to unintentional data disclosure. """

    def test_detects_sensitive_data_exposure_to_observer(self, parsed_daml_disclosure_risk):
        """ Verifies that known sensitive field names in a contract with observers are flagged. """
        # This rule would likely be configured with a list of sensitive keywords like "ssn", "password", etc.
        findings = check_observer_disclosure_risk(parsed_daml_disclosure_risk, sensitive_keywords=['ssn', 'salary'])
        assert len(findings) == 2
        messages = [f.message for f in findings]
        locations = [f.location for f in findings]
        assert "Field 'ssn' is visible to observer 'auditor'" in messages
        assert "Field 'salary' is visible to observer 'auditor'" in messages
        assert "DisclosureRisk:EmployeeData (line 3)" in locations

    def test_ignores_segregated_data_pattern(self, parsed_daml_disclosure_safe):
        """ Verifies that the data segregation pattern (using ContractIds) does not trigger a finding. """
        findings = check_observer_disclosure_risk(parsed_daml_disclosure_safe, sensitive_keywords=['ssn', 'salary'])
        assert len(findings) == 0