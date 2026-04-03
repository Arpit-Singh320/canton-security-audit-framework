# Canton & Daml Smart Contract Audit Methodology

## 1. Introduction

This document outlines a structured and comprehensive methodology for conducting security audits of Daml smart contracts intended for deployment on the Canton Network. The primary objective of an audit is to identify security vulnerabilities, design flaws, and deviations from best practices within the Daml codebase.

This methodology provides a repeatable framework for auditors to ensure a thorough review, covering everything from high-level business logic to low-level authorization details. It is designed to be used in conjunction with our static analysis tools and the [DAML Top 10 Vulnerabilities](./DAML_TOP_10.md) guide.

## 2. Audit Objectives

The core goals of a Daml contract audit are:

*   **Identify Security Vulnerabilities:** Uncover flaws in authorization, data disclosure, and state management that could be exploited by malicious actors.
*   **Verify Business Logic Correctness:** Ensure the implemented smart contracts accurately reflect the intended business rules and workflows.
*   **Assess Privacy & Data Segregation:** Confirm that the signatory and observer model correctly enforces the application's privacy requirements, preventing unauthorized data leakage.
*   **Analyze Liveness and Fault Tolerance:** Identify potential scenarios where a workflow could become stuck or where a malicious or non-responsive party could halt progress for others.
*   **Promote Best Practices:** Provide recommendations for improving code quality, maintainability, and adherence to established Daml design patterns.

## 3. Audit Phases

Our audit process is divided into five distinct phases, designed to build a deep understanding of the application and systematically uncover potential issues.

### Phase 1: Preparation and Scoping

This initial phase is critical for establishing context and defining the boundaries of the audit.

1.  **Project Kick-off:** A meeting with the development team to understand the application's business goals, architecture, and threat model. Key stakeholders, roles, and communication channels are established.
2.  **Information Gathering:** The audit team gathers all necessary materials, including:
    *   The target Git repository and a specific commit hash to be audited.
    *   Business requirements documents.
    *   System architecture diagrams, including the expected Canton topology.
    *   Any existing threat modeling documentation.
3.  **Scope Finalization:** A formal agreement on the scope of the audit. This includes a precise list of all `.daml` files, templates, and critical choices that are considered in-scope. Any out-of-scope components (e.g., UI, off-ledger services) are explicitly noted.
4.  **Environment Setup:** The auditor configures their local environment with the correct Daml SDK version (as specified in `daml.yaml`) and compiles the project to ensure a clean baseline.

### Phase 2: Automated Analysis

Automated tools are used to perform an initial sweep of the codebase to identify common issues and potential areas of concern.

1.  **Static Analysis:** Run the Canton Security Audit Framework's static analyzer against the codebase to detect common anti-patterns, such as:
    *   Authority leaks (e.g., signatories of a choice not being a subset of the contract's signatories).
    *   Potential disclosure bugs (e.g., observers being added without proper justification).
    *   Unused code or variables.
2.  **Dependency Review:** Analyze the `daml.yaml` file to understand project dependencies. While the Daml ecosystem is curated, it's important to be aware of the included libraries.
3.  **Code Metrics:** Generate metrics on code complexity, template size, and choice density to flag overly complex areas that may require deeper manual review.

### Phase 3: Manual Code Review

This is the core phase of the audit, where the auditor performs a deep, line-by-line analysis of the in-scope Daml code.

1.  **Authorization and Access Control:**
    *   **Signatories:** For each template, verify that the `signatory` set is minimal and correct. Does it accurately represent the parties who must authorize the contract's creation?
    *   **Observers:** For each template, scrutinize the `observer` set. Is every observer's access to the data justified by the business logic? Is there potential for unintended information leakage?
    *   **Controllers:** For each choice, verify that the `controller` set is minimal and appropriate. Can a party without a legitimate role in the workflow exercise a critical choice?
    *   **`ensure` clauses:** Check that preconditions, especially those involving input data or signatories, are robustly validated.

2.  **Business Logic and State Transitions:**
    *   **Workflow Integrity:** Trace the primary business workflows from contract creation to archival. Does the state machine behave as expected? Are there any dead ends or unintended states?
    *   **Choice Logic:** Examine the logic within each `do` block. Are contracts correctly created and archived? Are updates to contract data handled safely?
    *   **Edge Cases:** Consider non-happy-path scenarios. What happens if invalid data is provided? What if parties perform actions in an unexpected order?

3.  **Data Privacy and Disclosure:**
    *   **Choice Return Values:** Analyze what data is returned by choices. Does the return value leak information to the controller that they should not have access to?
    *   **Archival Consequences:** When a contract is archived, who is notified? Does the archival event itself leak information?
    *   **View-based Privacy:** Assess if the stakeholder model (signatories and observers) is sufficient for complex privacy needs or if a more granular, view-based pattern is required.

4.  **Economic and Liveness Attacks:**
    *   **Unbounded Creation:** Look for choices that could allow a malicious party to create an unbounded number of contracts, potentially consuming significant resources on a participant node.
    *   **Workflow Stalling:** Identify situations where a workflow requires action from a specific party. Can that party maliciously refuse to act, thereby blocking the workflow for all other participants (denial of service)?
    *   **Time-Dependencies:** Scrutinize the use of `getTime`. Since the time is provided by the submitter, ensure it's not the sole factor in critical financial or business decisions without corroboration. For time-sensitive logic (e.g., offer expiry), verify that it cannot be easily bypassed.

### Phase 4: Testing and Verification

In this phase, the auditor validates their findings by writing practical test cases.

1.  **Review Existing Tests:** Analyze the project's existing Daml Scripts (`daml test`). Evaluate their coverage of critical paths and edge cases.
2.  **Develop Proof-of-Concept Exploits:** For each identified vulnerability, write a new `Daml.Script` that demonstrates the exploit. This provides concrete, repeatable evidence for the finding.
3.  **Scenario Analysis:** Write scripts to model complex multi-party interactions, simulating both cooperative and adversarial behavior to test the resilience of the protocol.

### Phase 5: Reporting and Remediation

The final phase involves documenting the findings and collaborating with the development team on fixes.

1.  **Drafting the Audit Report:** A comprehensive report is created, containing:
    *   **Executive Summary:** A high-level overview of the audit's scope, methodology, and key findings for a non-technical audience.
    *   **Vulnerability Details:** A detailed section for each finding, including a title, severity level, description, impact analysis, proof-of-concept script, and clear remediation recommendations.
    *   **Informational Findings:** Notes on code quality, gas-like inefficiencies, and deviations from best practices that are not direct security risks.
2.  **Presentation and Review:** The draft report is presented to the development team. This is a collaborative session to ensure findings are understood and to clarify any technical details.
3.  **Remediation and Re-audit:** The development team implements fixes for the identified issues. Once complete, the auditor performs a targeted re-audit to verify that each fix is correct and has not introduced new vulnerabilities.
4.  **Final Report Delivery:** A final report is issued, incorporating the results of the re-audit and marking the status of each vulnerability (e.g., "Fixed", "Acknowledged", "Mitigated").

## 4. Severity Levels

Findings are categorized using the following severity levels to help prioritize remediation efforts:

*   **Critical:** Vulnerabilities that can lead to a direct loss or theft of assets, a complete breakdown of the business logic, or irreversible state corruption. Require immediate attention.
*   **High:** Flaws that seriously compromise the integrity or privacy of the system, such as allowing unauthorized parties to perform critical actions or view sensitive data.
*   **Medium:** Vulnerabilities that could lead to unintended behavior, workflow deadlocks, or minor data leaks. They represent a tangible but less immediate risk.
*   **Low:** Issues that are difficult to exploit or have minimal impact, such as minor deviations from best practices or potential for minor resource consumption attacks.
*   **Informational:** Recommendations for improving code clarity, maintainability, or adherence to Daml idioms, without posing a direct security risk.