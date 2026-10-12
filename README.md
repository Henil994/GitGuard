# GitGuard — GitHub Secret Scanner

GitGuard is a Python-based defensive security tool that scans public, non-fork GitHub repositories for potential exposed secrets in Git history and current files using [Gitleaks](https://github.com/gitleaks/gitleaks).

It generates JSON and HTML reports containing finding metadata, risk-prioritization scores, finding categories, and approximate historical/current-file correlation.

## Features

- Discovers public, non-fork repositories through the GitHub REST API.
- Scans Git history for potential secrets using Gitleaks.
- Separately scans checked-out repository files.
- Classifies findings into broad categories, such as API keys, access tokens, passwords, cloud credentials, and private keys.
- Assigns heuristic risk-prioritization scores.
- Deduplicates findings using safe metadata.
- Correlates historical findings with current-file findings using rule and file path.
- Generates JSON and HTML security reports with summary statistics.
- Excludes detected secret values from GitGuard's normalized findings.
- Removes temporary repository clones and intermediate scan reports after processing.
- Includes offline regression tests using synthetic data.

## Technology Stack

- Python 3
- Git
- Gitleaks
- GitHub REST API
- Requests

## Requirements

- Python 3
- Git
- Gitleaks installed and available on your `PATH`
- Internet access to query the GitHub API and clone public repositories

## Installation

Clone the repository and enter its directory:

```bash
git clone https://github.com/Henil994/GitGuard.git
cd GitGuard
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Install Gitleaks separately using its official installation instructions:

https://github.com/gitleaks/gitleaks

Verify the tools are available:

```bash
python --version
git --version
gitleaks --help
```

## Usage

### Scan a GitHub profile

Pass a GitHub username:

```bash
python src/main.py Henil994
```

You can also pass a GitHub profile URL:

```bash
python src/main.py https://github.com/Henil994
```

GitGuard discovers public, non-fork repositories, scans each repository's Git history and current files, and produces consolidated reports.

### Run offline regression tests

```bash
python src/main.py --self-test
```

The self-test suite uses synthetic test data and does not contact GitHub or clone repositories.

## Reports

GitGuard saves JSON and HTML reports in the local `reports/` directory.

Reports include:

- Number of repositories discovered and scanned
- Potential findings and risk-prioritization summaries
- Finding categories
- Repository-level finding counts
- Historical/current-file correlation results
- Finding metadata, including rule, file path, commit, and available location information
- Scan limitations and review guidance

Intermediate Gitleaks reports and temporary repository clones are removed after processing.

## Understanding Risk and Exposure Status

GitGuard's risk scores are heuristic prioritization scores. They are not CVSS scores and do not establish that a credential is valid, active, or exploitable.

Historical/current-file correlation is approximate. It compares a finding's rule and file path rather than a unique secret fingerprint.

- **Current match (approximate):** A matching rule and file path were found in the current-file scan.
- **Historical only:** A historical finding did not match the current-file scan using that approximate method.
- **Unknown:** The current-file scan could not provide a usable result.

A historical-only finding does not prove that a credential is invalid or that all copies have been removed.

If a credential was exposed publicly, revoke or rotate it through the relevant provider. Removing a credential from the latest file does not remove it from earlier Git commits.

## Limitations

- Only public, non-fork repositories are scanned.
- Private repositories are not supported by the current implementation.
- Detection can produce false positives and false negatives.
- Classification and risk scoring are heuristic.
- Correlation does not uniquely identify the same secret across commits.
- Results depend on the Gitleaks version, rules, and scan behavior.
- A successful scan does not prove that a repository or GitHub profile is secure.
- The current implementation uses unauthenticated GitHub API requests, so API rate limits may restrict discovery.

## Ethical Use

Use GitGuard for defensive security research on public repositories or repositories for which you have explicit authorization.

Respect API rate limits, applicable terms of service, and the privacy of repository owners. Do not use findings to access systems or accounts without permission.

## Author

**Henil Patel**

- GitHub: https://github.com/Henil994
- TryHackMe: https://tryhackme.com/p/Henil8994

## Disclaimer

GitGuard is intended for defensive security research, secret-exposure detection, and educational use. Findings must be validated responsibly. The tool is provided without a guarantee that all exposed secrets will be detected.
