# Canton Security Audit Framework

This repository contains a static analysis tool and audit methodology for securing Daml smart contracts within the Canton Network.  It helps developers and auditors identify common vulnerabilities before they reach production.

## Overview

The Canton Security Audit Framework provides:

*   **Static Analysis Tool:** An open-source tool designed to automatically detect potential vulnerabilities in Daml code.  This tool analyzes Daml contracts for common issues such as authority leaks, choice abuse, time-sensitive attacks, and information disclosure bugs.
*   **Audit Methodology:** A comprehensive audit methodology specifically tailored for Daml smart contracts in the Canton Network. This methodology is the Canton equivalent of the OWASP Smart Contract Top 10, providing a structured approach to identifying and mitigating security risks.
*   **CI/CD Integration:**  Guidance and scripts to integrate the static analysis tool into your CI/CD pipeline, enabling automated security scanning on every pull request. This ensures continuous monitoring and prevention of security regressions.

## Getting Started

### Prerequisites

*   Daml SDK (version 3.1.0 or higher)
*   Python 3.7 or higher (for the static analysis tool)
*   Git

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/YOUR_USERNAME/canton-security-audit-framework.git
    cd canton-security-audit-framework
    ```

2.  **Install Python dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Build the Daml project (if applicable):**  If you are testing the analyzer on a pre-existing Daml project, build it:

    ```bash
    daml build
    ```

### Running the Static Analysis Tool

The static analysis tool is a Python script that analyzes Daml code for potential vulnerabilities.

1.  **Navigate to the `analyzer` directory:**  Assume the Python scripts are located in a subfolder called `analyzer`.

    ```bash
    cd analyzer
    ```

2.  **Run the analyzer:**

    ```bash
    python analyze.py --daml-file path/to/your/contract.daml
    ```

    Replace `path/to/your/contract.daml` with the path to your Daml contract file.  You can also specify a directory containing multiple Daml files.

    ```bash
    python analyze.py --daml-directory path/to/your/daml/project
    ```

3.  **Review the results:**  The analyzer will output a report listing any potential vulnerabilities found in the code, along with recommendations for remediation.

### Integrating with CI/CD

To integrate the static analysis tool into your CI/CD pipeline, you can use the provided scripts and configurations.

1.  **Add a step to your CI/CD pipeline to run the analyzer:**  This step should execute the `analyze.py` script with the appropriate parameters.

    Example (using GitHub Actions):

    ```yaml
    name: Security Audit

    on:
      pull_request:
        branches: [ main ]

    jobs:
      audit:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v3
          - name: Set up Python 3.x
            uses: actions/setup-python@v3
            with:
              python-version: '3.x'
          - name: Install dependencies
            run: |
              python -m pip install --upgrade pip
              pip install -r analyzer/requirements.txt
          - name: Run static analysis
            run: python analyzer/analyze.py --daml-directory daml/src
    ```

    Replace `daml/src` with the path to the directory containing your Daml contracts.  Adjust the Python version and dependencies as needed.

2.  **Configure the analyzer to fail the build if vulnerabilities are found:**  You can modify the `analyze.py` script to exit with a non-zero status code if any vulnerabilities are detected. This will cause the CI/CD pipeline to fail, preventing insecure code from being merged into the main branch.

### Audit Methodology

The audit methodology provides a structured approach to identifying and mitigating security risks in Daml smart contracts.  It covers the following key areas:

1.  **Authority Leaks:**  Ensuring that only authorized parties can perform sensitive actions.
2.  **Choice Abuse:**  Preventing unauthorized or malicious use of choices.
3.  **Time-Sensitive Attacks:**  Protecting against attacks that exploit timing vulnerabilities.
4.  **Information Disclosure Bugs:**  Preventing unauthorized access to sensitive data.
5.  **Resource Exhaustion:**  Avoiding denial-of-service attacks that consume excessive resources.
6.  **Re-entrancy Vulnerabilities:** Ensuring the code is resilient against re-entrancy attacks.
7.  **Arithmetic Overflows/Underflows:** Preventing unintended behavior due to integer limits.
8.  **Access Control Issues:** Ensuring proper access control mechanisms are in place.
9.  **Unvalidated Inputs:**  Validating all inputs to prevent injection attacks.
10. **Logic Errors:** Addressing flaws in the core contract logic.

For each area, the methodology provides:

*   **Description:** A detailed explanation of the vulnerability.
*   **Examples:** Real-world examples of how the vulnerability can be exploited.
*   **Mitigation Strategies:**  Recommended practices for preventing the vulnerability.
*   **Testing Techniques:**  Techniques for verifying that the vulnerability has been addressed.

A detailed guide to the audit methodology can be found in the `audit_methodology.md` file.

## Contributing

We welcome contributions to the Canton Security Audit Framework.  Please see the `CONTRIBUTING.md` file for details on how to contribute.

## License

This project is licensed under the Apache 2.0 License - see the `LICENSE` file for details.