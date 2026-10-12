import argparse
import html
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests


ROOT = Path.home() / "GitGuard"
REPOS_DIR = ROOT / "repos"
REPORTS_DIR = ROOT / "reports"
API = "https://api.github.com"


def get_username(value):
    value = value.strip()

    if "://" in value:
        parsed = urlparse(value)

        if parsed.scheme != "https" or parsed.netloc.lower() not in {
            "github.com",
            "www.github.com",
        }:
            raise ValueError("Enter a github.com profile URL.")

        parts = parsed.path.strip("/").split("/")

        if len(parts) != 1:
            raise ValueError(
                "Enter a profile URL, not a repository URL."
            )

        value = parts[0]

    if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", value):
        raise ValueError("Invalid GitHub username.")

    return value


def discover_repositories(username):
    repos = []
    page = 1

    while True:
        response = requests.get(
            f"{API}/users/{username}/repos",
            params={
                "type": "public",
                "per_page": 100,
                "page": page,
                "sort": "updated",
            },
            headers={
                "Accept": "application/vnd.github+json"
            },
            timeout=30,
        )

        if response.status_code == 404:
            raise ValueError(
                "GitHub profile was not found."
            )

        if response.status_code == 403:
            raise RuntimeError(
                "GitHub API rate limit or access restriction. "
                "Try later."
            )

        response.raise_for_status()

        batch = response.json()

        if not isinstance(batch, list):
            raise RuntimeError(
                "Unexpected response from GitHub API."
            )

        repos.extend(batch)

        if len(batch) < 100:
            break

        page += 1

    return [
        repo
        for repo in repos
        if not repo.get("fork", False)
    ]


def classify_finding(
    rule,
    description="",
    tags=None,
):
    """
    Classify a Gitleaks finding into a broad security category.

    This is heuristic classification based on rule ID,
    description, and tags. It does not validate whether
    a credential is real.
    """
    rule_text = str(
        rule or ""
    ).lower()

    description_text = str(
        description or ""
    ).lower()

    if isinstance(tags, list):
        tag_text = " ".join(
            str(tag).lower()
            for tag in tags
        )
    else:
        tag_text = ""

    text = " ".join(
        [
            rule_text,
            description_text,
            tag_text,
        ]
    )

    if any(
        keyword in text
        for keyword in (
            "private-key",
            "private_key",
            "private key",
            "ssh-key",
            "ssh key",
            "pem",
        )
    ):
        return "Private Key"

    if any(
        keyword in text
        for keyword in (
            "aws",
            "amazon",
            "access-key",
            "secret-key",
            "cloud credential",
        )
    ):
        return "Cloud Credential"

    if any(
        keyword in text
        for keyword in (
            "github",
            "gitlab",
            "bitbucket",
            "personal-access-token",
            "oauth",
            "access-token",
            "access_token",
            "token",
        )
    ):
        return "Access Token"

    if any(
        keyword in text
        for keyword in (
            "password",
            "passwd",
            "passphrase",
        )
    ):
        return "Password"

    if any(
        keyword in text
        for keyword in (
            "database",
            "db-",
            "connection-string",
            "connection string",
            "jdbc",
            "mongodb",
            "mysql",
            "postgres",
            "redis",
        )
    ):
        return "Database Credential"

    if any(
        keyword in text
        for keyword in (
            "api-key",
            "api_key",
            "apikey",
            "api key",
            "generic-api",
        )
    ):
        return "API Key"

    return "Potential Secret"


def calculate_risk(
    category,
    rule,
    correlation_status="UNKNOWN",
):
    """
    Calculate GitGuard's prioritization score.

    This is NOT CVSS and does not prove exploitability or
    credential validity.

    Score factors:
      - Secret category
      - Approximate current exposure status
      - Historical-only exposure
      - Unknown correlation state
    """
    category_scores = {
        "Private Key": 85,
        "Cloud Credential": 80,
        "Access Token": 78,
        "Password": 72,
        "Database Credential": 75,
        "API Key": 60,
        "Potential Secret": 40,
    }

    score = category_scores.get(
        category,
        40,
    )

    if correlation_status == "CURRENT_MATCH_APPROXIMATE":
        score += 10
    elif correlation_status == "HISTORICAL_ONLY":
        score += 0
    else:
        score += 3

    score = min(
        max(score, 0),
        100,
    )

    if score >= 80:
        level = "HIGH"
    elif score >= 60:
        level = "MEDIUM"
    else:
        level = "REVIEW"

    return {
        "level": level,
        "score": score,
    }


def safe_gitleaks_findings(report_path):
    """
    Extract safe metadata from a Gitleaks JSON report.

    Secret values are intentionally excluded from GitGuard's
    consolidated reports.
    """
    try:
        raw = json.loads(
            report_path.read_text(
                encoding="utf-8"
            )
        )
    except (OSError, json.JSONDecodeError):
        return [], False

    if not isinstance(raw, list):
        return [], False

    findings = []

    for item in raw:
        if not isinstance(item, dict):
            continue

        tags = item.get("Tags", [])

        if isinstance(tags, list):
            safe_tags = [
                str(tag)[:100]
                for tag in tags
            ]
        else:
            safe_tags = []

        finding = {
            "rule": str(
                item.get(
                    "RuleID",
                    "unknown",
                )
            )[:100],
            "description": str(
                item.get(
                    "Description",
                    "",
                )
            )[:500],
            "file": str(
                item.get(
                    "File",
                    "unknown",
                )
            )[:300],
            "commit": str(
                item.get(
                    "Commit",
                    "",
                )
            )[:40],
            "line": item.get("StartLine"),
            "end_line": item.get("EndLine"),
            "column": item.get("StartColumn"),
            "end_column": item.get("EndColumn"),
            "author": str(
                item.get(
                    "Author",
                    "",
                )
            )[:200],
            "date": str(
                item.get(
                    "Date",
                    "",
                )
            )[:100],
            "tags": safe_tags,
            "description_note": (
                "Potential secret detected. Verify privately "
                "and rotate the credential if exposed."
            ),
        }

        category = classify_finding(
            finding["rule"],
            finding["description"],
            finding["tags"],
        )

        finding["category"] = category

        # Correlation is not known until the current-file scan.
        finding["correlation_status"] = "UNKNOWN"

        risk = calculate_risk(
            category,
            finding["rule"],
            finding["correlation_status"],
        )

        finding["risk_level"] = risk["level"]
        finding["risk_score"] = risk["score"]

        findings.append(finding)

    return findings, True


def normalize_file_path(value):
    """Normalize file paths before comparing scan results."""
    path = str(
        value or ""
    ).replace(
        "\\",
        "/",
    )

    while path.startswith("./"):
        path = path[2:]

    return path


def correlate_findings(
    history_findings,
    current_findings,
):
    """
    Correlate historical findings with current-file findings.

    This intentionally uses safe metadata only. It does not
    compare or store secret values.

    Correlation is approximate because rule + file path cannot
    uniquely identify the same secret.
    """
    current_keys = {
        (
            str(
                finding.get(
                    "rule",
                    "",
                )
            ).lower(),
            normalize_file_path(
                finding.get(
                    "file",
                    "",
                )
            ).lower(),
        )
        for finding in current_findings
    }

    correlated = []

    for finding in history_findings:
        key = (
            str(
                finding.get(
                    "rule",
                    "",
                )
            ).lower(),
            normalize_file_path(
                finding.get(
                    "file",
                    "",
                )
            ).lower(),
        )

        updated = dict(finding)

        if key in current_keys:
            status = "CURRENT_MATCH_APPROXIMATE"
        else:
            status = "HISTORICAL_ONLY"

        updated["correlation_status"] = status
        updated["current_file_match"] = (
            status == "CURRENT_MATCH_APPROXIMATE"
        )

        risk = calculate_risk(
            updated.get(
                "category",
                "Potential Secret",
            ),
            updated.get(
                "rule",
                "",
            ),
            status,
        )

        updated["risk_level"] = risk["level"]
        updated["risk_score"] = risk["score"]

        correlated.append(updated)

    return correlated


def finding_identity(finding):
    """
    Build a deterministic identity for deduplicating findings.

    Secret values are deliberately not used.
    """
    return (
        str(
            finding.get(
                "rule",
                "",
            )
        ).lower(),
        normalize_file_path(
            finding.get(
                "file",
                "",
            )
        ).lower(),
        str(
            finding.get(
                "commit",
                "",
            )
        ).lower(),
        finding.get("line"),
        finding.get("column"),
    )


def deduplicate_findings(findings):
    """
    Remove duplicate findings while preserving order.
    """
    unique = []
    seen = set()

    for finding in findings:
        identity = finding_identity(
            finding
        )

        if identity in seen:
            continue

        seen.add(identity)
        unique.append(finding)

    return unique


def scan_repository(repo):
    name = repo["name"]

    destination = (
        REPOS_DIR
        / f'{repo["id"]}-{name}'
    )

    temporary_report = (
        REPORTS_DIR
        / f".gitleaks-{repo['id']}.json"
    )

    current_report = (
        REPORTS_DIR
        / f".gitleaks-current-{repo['id']}.json"
    )

    result = {
        "name": name,
        "url": repo["html_url"],
        "status": "failed",
        "finding_count": 0,
        "findings": [],
        "note": "",
    }

    try:
        if destination.exists():
            shutil.rmtree(
                destination
            )

        clone = subprocess.run(
            [
                "git",
                "clone",
                "--quiet",
                repo["clone_url"],
                str(destination),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if clone.returncode != 0:
            result["note"] = (
                "Clone failed; repository may be unavailable "
                "or too large."
            )
            return result

        history_scan = subprocess.run(
            [
                "gitleaks",
                "git",
                str(destination),
                "--redact",
                "--report-format",
                "json",
                "--report-path",
                str(temporary_report),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        if history_scan.returncode not in (
            0,
            1,
        ):
            result["note"] = (
                "Git-history scan failed; check the local "
                "Gitleaks installation."
            )
            return result

        findings, report_readable = (
            safe_gitleaks_findings(
                temporary_report
            )
        )

        if not report_readable:
            result["note"] = (
                "Could not read Git-history scan output; "
                "result is incomplete."
            )
            return result

        findings = deduplicate_findings(
            findings
        )

        current_scan = subprocess.run(
            [
                "gitleaks",
                "dir",
                str(destination),
                "--redact",
                "--report-format",
                "json",
                "--report-path",
                str(current_report),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        current_readable = False
        current_findings = []

        if current_scan.returncode in (
            0,
            1,
        ):
            (
                current_findings,
                current_readable,
            ) = safe_gitleaks_findings(
                current_report
            )

            if current_readable:
                current_findings = (
                    deduplicate_findings(
                        current_findings
                    )
                )

        if current_readable:
            findings = correlate_findings(
                findings,
                current_findings,
            )
        else:
            for finding in findings:
                finding[
                    "correlation_status"
                ] = "UNKNOWN"

                finding[
                    "current_file_match"
                ] = None

                risk = calculate_risk(
                    finding.get(
                        "category",
                        "Potential Secret",
                    ),
                    finding.get(
                        "rule",
                        "",
                    ),
                    "UNKNOWN",
                )

                finding["risk_level"] = (
                    risk["level"]
                )

                finding["risk_score"] = (
                    risk["score"]
                )

        result["findings"] = findings
        result["finding_count"] = len(findings)
        result["status"] = "completed"

        if not current_readable:
            result["note"] = (
                "Git-history scan completed, but the current-file "
                "check was unavailable. Exposure status is unknown."
            )
        elif findings:
            result["note"] = (
                "Potential matches require manual verification. "
                "Current/history correlation is approximate."
            )
        else:
            result["note"] = (
                "No matching secrets detected by Gitleaks."
            )

        return result

    except subprocess.TimeoutExpired:
        result["note"] = (
            "Scan timed out; repository was not fully scanned."
        )
        return result

    except OSError:
        result["note"] = (
            "A required command or file operation failed."
        )
        return result

    finally:
        temporary_report.unlink(
            missing_ok=True
        )

        current_report.unlink(
            missing_ok=True
        )

        if destination.exists():
            shutil.rmtree(
                destination,
                ignore_errors=True,
            )


def build_report(
    username,
    repos,
    results,
):
    completed = sum(
        result["status"] == "completed"
        for result in results
    )

    total_findings = sum(
        result["finding_count"]
        for result in results
    )

    high_findings = 0
    medium_findings = 0
    review_findings = 0

    category_counts = {}

    correlation_counts = {
        "CURRENT_MATCH_APPROXIMATE": 0,
        "HISTORICAL_ONLY": 0,
        "UNKNOWN": 0,
    }

    repository_findings = []

    for repository in results:
        repository_findings.append(
            {
                "name": repository["name"],
                "findings": repository[
                    "finding_count"
                ],
            }
        )

        for finding in repository["findings"]:
            risk_level = finding.get(
                "risk_level",
                "REVIEW",
            )

            if risk_level == "HIGH":
                high_findings += 1
            elif risk_level == "MEDIUM":
                medium_findings += 1
            else:
                review_findings += 1

            category = finding.get(
                "category",
                "Potential Secret",
            )

            category_counts[category] = (
                category_counts.get(
                    category,
                    0,
                )
                + 1
            )

            correlation_status = finding.get(
                "correlation_status",
                "UNKNOWN",
            )

            if correlation_status not in correlation_counts:
                correlation_status = "UNKNOWN"

            correlation_counts[
                correlation_status
            ] += 1

    repository_findings.sort(
        key=lambda item: item["findings"],
        reverse=True,
    )

    return {
        "profile": username,
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "public_non_fork_repositories_discovered": len(
            repos
        ),
        "repositories_completed": completed,
        "repositories_failed_or_incomplete": (
            len(results) - completed
        ),
        "potential_findings": total_findings,
        "risk_summary": {
            "high": high_findings,
            "medium": medium_findings,
            "review": review_findings,
        },
        "category_summary": category_counts,
        "correlation_summary": correlation_counts,
        "repositories_ranked_by_findings": (
            repository_findings
        ),
        "limitations": [
            "Only public, non-fork repositories are scanned.",
            "Gitleaks findings may be false positives.",
            (
                "Finding categories and risk scores are "
                "heuristic classifications."
            ),
            (
                "Risk scores are GitGuard prioritization scores, "
                "not CVSS scores."
            ),
            (
                "Risk scores do not prove that a credential "
                "is valid or exploitable."
            ),
            (
                "Current/history correlation uses rule and "
                "file path as a safe approximation and does "
                "not uniquely identify a historical secret."
            ),
            "No findings does not prove the profile is secure.",
            (
                "A finding does not establish that a credential "
                "is valid or currently usable."
            ),
        ],
    }


def write_reports(
    username,
    repos,
    results,
):
    timestamp = datetime.now(
        timezone.utc
    ).strftime(
        "%Y%m%d-%H%M%S"
    )

    base = (
        REPORTS_DIR
        / f"{username}-{timestamp}"
    )

    report = build_report(
        username,
        repos,
        results,
    )

    json_path = base.with_suffix(
        ".json"
    )

    html_path = base.with_suffix(
        ".html"
    )

    json_path.write_text(
        json.dumps(
            report,
            indent=2,
        ),
        encoding="utf-8",
    )

    rows = []

    for repository in results:
        findings_html = []

        for finding in repository["findings"]:
            correlation_status = finding.get(
                "correlation_status",
                "UNKNOWN",
            )

            if (
                correlation_status
                == "CURRENT_MATCH_APPROXIMATE"
            ):
                exposure_label = (
                    "Current match (approximate)"
                )
            elif (
                correlation_status
                == "HISTORICAL_ONLY"
            ):
                exposure_label = (
                    "Historical only"
                )
            else:
                exposure_label = "Unknown"

            line = finding.get("line")
            end_line = finding.get("end_line")
            column = finding.get("column")
            end_column = finding.get("end_column")

            description = finding.get(
                "description",
                "",
            )

            author = finding.get(
                "author",
                "",
            )

            date = finding.get(
                "date",
                "",
            )

            tags = finding.get(
                "tags",
                [],
            )

            tags_label = (
                ", ".join(tags)
                if tags
                else "None"
            )

            category = finding.get(
                "category",
                "Potential Secret",
            )

            risk_level = finding.get(
                "risk_level",
                "REVIEW",
            )

            risk_score = finding.get(
                "risk_score",
                40,
            )

            findings_html.append(
                "<li>"
                f"<b>Rule:</b> "
                f"{html.escape(finding['rule'])}<br>"
                f"<b>Category:</b> "
                f"{html.escape(category)}<br>"
                f"<b>Risk:</b> "
                f"{html.escape(risk_level)} "
                f"({risk_score}/100)<br>"
                f"<b>Description:</b> "
                f"{html.escape(description)}<br>"
                f"<b>File:</b> "
                f"{html.escape(finding['file'])}<br>"
                f"<b>Line:</b> "
                f"{html.escape(str(line) if line is not None else 'Unknown')}"
                f" - "
                f"{html.escape(str(end_line) if end_line is not None else 'Unknown')}"
                f"<br>"
                f"<b>Column:</b> "
                f"{html.escape(str(column) if column is not None else 'Unknown')}"
                f" - "
                f"{html.escape(str(end_column) if end_column is not None else 'Unknown')}"
                f"<br>"
                f"<b>Commit:</b> "
                f"{html.escape(finding['commit'])}<br>"
                f"<b>Author:</b> "
                f"{html.escape(author)}<br>"
                f"<b>Date:</b> "
                f"{html.escape(date)}<br>"
                f"<b>Tags:</b> "
                f"{html.escape(tags_label)}<br>"
                f"<b>Exposure status:</b> "
                f"{html.escape(exposure_label)}"
                "</li>"
            )

        details = (
            "<ul>"
            + "".join(findings_html)
            + "</ul>"
            if findings_html
            else "No Gitleaks matches reported."
        )

        rows.append(
            "<tr>"
            f"<td><a href='"
            f"{html.escape(repository['url'], quote=True)}'>"
            f"{html.escape(repository['name'])}"
            "</a></td>"
            f"<td>{html.escape(repository['status'])}</td>"
            f"<td>{repository['finding_count']}</td>"
            f"<td>{details}</td>"
            f"<td>{html.escape(repository['note'])}</td>"
            "</tr>"
        )

    category_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(category)}</td>"
        f"<td>{count}</td>"
        f"</tr>"
        for category, count in sorted(
            report["category_summary"].items()
        )
    )

    correlation_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(status)}</td>"
        f"<td>{count}</td>"
        f"</tr>"
        for status, count in report[
            "correlation_summary"
        ].items()
    )

    ranked_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(item['name'])}</td>"
        f"<td>{item['findings']}</td>"
        f"</tr>"
        for item in report[
            "repositories_ranked_by_findings"
        ]
    )

    page = f"""<!doctype html>
<html lang="en">

<head>

<meta charset="utf-8">

<meta name="viewport"
      content="width=device-width, initial-scale=1">

<title>GitGuard Security Report</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 2rem;
    color: #222;
}}

.card {{
    display: inline-block;
    padding: 1rem;
    margin: .4rem;
    border: 1px solid #ccc;
    border-radius: 8px;
    min-width: 140px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}}

th,
td {{
    border: 1px solid #ddd;
    padding: .7rem;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f2f2f2;
}}

li {{
    margin-bottom: .8rem;
    overflow-wrap: anywhere;
}}

.note {{
    max-width: 1000px;
    line-height: 1.5;
}}

</style>

</head>

<body>

<h1>GitGuard Security Report</h1>

<p>
<b>GitHub profile:</b>
{html.escape(username)}
</p>

<p>
<b>Generated (UTC):</b>
{html.escape(report['generated_at_utc'])}
</p>

<div class="card">
<b>Repositories found</b>
<h2>
{report['public_non_fork_repositories_discovered']}
</h2>
</div>

<div class="card">
<b>Scans completed</b>
<h2>
{report['repositories_completed']}
</h2>
</div>

<div class="card">
<b>Potential findings</b>
<h2>
{report['potential_findings']}
</h2>
</div>

<div class="card">
<b>High risk</b>
<h2>
{report['risk_summary']['high']}
</h2>
</div>

<div class="card">
<b>Medium risk</b>
<h2>
{report['risk_summary']['medium']}
</h2>
</div>

<div class="card">
<b>Review</b>
<h2>
{report['risk_summary']['review']}
</h2>
</div>

<h2>Risk Summary</h2>

<table>

<thead>
<tr>
<th>Risk Level</th>
<th>Findings</th>
</tr>
</thead>

<tbody>

<tr>
<td>HIGH</td>
<td>{report['risk_summary']['high']}</td>
</tr>

<tr>
<td>MEDIUM</td>
<td>{report['risk_summary']['medium']}</td>
</tr>

<tr>
<td>REVIEW</td>
<td>{report['risk_summary']['review']}</td>
</tr>

</tbody>

</table>

<h2>Finding Categories</h2>

<table>

<thead>
<tr>
<th>Category</th>
<th>Findings</th>
</tr>
</thead>

<tbody>

{category_rows}

</tbody>

</table>

<h2>Exposure Correlation</h2>

<table>

<thead>
<tr>
<th>Status</th>
<th>Findings</th>
</tr>
</thead>

<tbody>

{correlation_rows}

</tbody>

</table>

<h2>Repositories Ranked by Findings</h2>

<table>

<thead>
<tr>
<th>Repository</th>
<th>Potential findings</th>
</tr>
</thead>

<tbody>

{ranked_rows}

</tbody>

</table>

<h2>Repository Results</h2>

<table>

<thead>

<tr>
<th>Repository</th>
<th>Status</th>
<th>Potential findings</th>
<th>Finding details</th>
<th>Notes</th>
</tr>

</thead>

<tbody>

{''.join(rows)}

</tbody>

</table>

<h2>Limitations</h2>

<ul>

{
    ''.join(
        '<li>'
        + html.escape(item)
        + '</li>'
        for item in report["limitations"]
    )
}

</ul>

<p class="note">

<b>Security note:</b>

GitGuard deliberately excludes detected secret values from
the consolidated report. A current-file match is based on
Gitleaks rule and file path, not a unique secret fingerprint.

If a real credential was exposed, revoke or rotate it.
Removing a credential from the latest file does not remove
it from Git history.

Risk scores are GitGuard prioritization scores and are not
CVSS scores.

</p>

</body>

</html>
"""

    html_path.write_text(
        page,
        encoding="utf-8",
    )

    return {
        **report,
        "json_report": str(
            json_path
        ),
        "html_report": str(
            html_path
        ),
    }


def run_self_tests():
    """
    Run offline regression tests using synthetic data.

    No GitHub API requests, repository clones, or real secrets
    are used.
    """
    print("GitGuard Phase 1 regression tests")
    print("=" * 45)

    failures = []

    def check(name, condition):
        if condition:
            print(f"[PASS] {name}")
        else:
            print(f"[FAIL] {name}")
            failures.append(name)

    # Classification tests.
    check(
        "API key classification",
        classify_finding(
            "generic-api-key",
            "Generic API Key",
            ["api"],
        ) == "API Key",
    )

    check(
        "Cloud credential classification",
        classify_finding(
            "aws-access-token",
            "AWS credential",
            ["aws"],
        ) == "Cloud Credential",
    )

    check(
        "Access token classification",
        classify_finding(
            "github-pat",
            "GitHub personal access token",
            ["token"],
        ) == "Access Token",
    )

    check(
        "Private key classification",
        classify_finding(
            "private-key",
            "Private key",
            ["key"],
        ) == "Private Key",
    )

    check(
        "Password classification",
        classify_finding(
            "password",
            "Password",
            [],
        ) == "Password",
    )

    # Risk tests.
    api_risk = calculate_risk(
        "API Key",
        "generic-api-key",
        "HISTORICAL_ONLY",
    )

    check(
        "API key historical risk",
        api_risk["level"] == "MEDIUM"
        and api_risk["score"] == 60,
    )

    current_api_risk = calculate_risk(
        "API Key",
        "generic-api-key",
        "CURRENT_MATCH_APPROXIMATE",
    )

    check(
        "Current API key risk increases",
        current_api_risk["score"] == 70,
    )

    private_key_risk = calculate_risk(
        "Private Key",
        "private-key",
        "CURRENT_MATCH_APPROXIMATE",
    )

    check(
        "Current private key is HIGH",
        private_key_risk["level"] == "HIGH"
        and private_key_risk["score"] == 95,
    )

    # Deduplication test.
    sample = {
        "rule": "generic-api-key",
        "file": "./config/test.py",
        "commit": "abc123",
        "line": 10,
        "column": 5,
    }

    duplicates = [
        sample.copy(),
        sample.copy(),
    ]

    deduplicated = deduplicate_findings(
        duplicates
    )

    check(
        "Duplicate findings removed",
        len(deduplicated) == 1,
    )

    # Correlation tests.
    history = [
        {
            "rule": "generic-api-key",
            "file": "config.yaml",
            "commit": "abc123",
            "category": "API Key",
        },
        {
            "rule": "password",
            "file": "old/config.py",
            "commit": "def456",
            "category": "Password",
        },
    ]

    current = [
        {
            "rule": "generic-api-key",
            "file": "./config.yaml",
        },
    ]

    correlated = correlate_findings(
        history,
        current,
    )

    check(
        "Current/history correlation",
        correlated[0]["correlation_status"]
        == "CURRENT_MATCH_APPROXIMATE",
    )

    check(
        "Historical-only detection",
        correlated[1]["correlation_status"]
        == "HISTORICAL_ONLY",
    )

    # Secret-value safety test.
    fake_secret = "THIS_IS_NOT_A_REAL_SECRET"

    fixture = [
        {
            "RuleID": "generic-api-key",
            "Description": "Synthetic test",
            "File": "test.py",
            "Commit": "abc123",
            "StartLine": 1,
            "StartColumn": 1,
            "Author": "Test",
            "Date": "2026-10-07T00:00:00Z",
            "Tags": ["test"],
            "Secret": fake_secret,
            "Match": fake_secret,
        }
    ]

    fixture_path = (
        REPORTS_DIR
        / ".gitguard-self-test.json"
    )

    try:
        REPORTS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        fixture_path.write_text(
            json.dumps(fixture),
            encoding="utf-8",
        )

        parsed, readable = (
            safe_gitleaks_findings(
                fixture_path
            )
        )

        check(
            "Synthetic Gitleaks report readable",
            readable and len(parsed) == 1,
        )

        serialized = json.dumps(
            parsed
        )

        check(
            "Secret value excluded from normalized finding",
            fake_secret not in serialized,
        )

    finally:
        fixture_path.unlink(
            missing_ok=True
        )

    print("=" * 45)

    if failures:
        print(
            f"FAILED: {len(failures)} test(s)."
        )

        for failure in failures:
            print(
                f" - {failure}"
            )

        return False

    print(
        "SUCCESS: All Phase 1 regression tests passed."
    )

    return True


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Scan public, non-fork GitHub repositories "
            "for potential secrets using Gitleaks."
        )
    )

    parser.add_argument(
        "username",
        nargs="?",
        help="GitHub username or profile URL",
    )

    parser.add_argument(
        "--self-test",
        action="store_true",
        help=(
            "Run offline Phase 1 regression tests "
            "without contacting GitHub."
        ),
    )

    args = parser.parse_args()

    if args.self_test:
        success = run_self_tests()
        sys.exit(
            0 if success else 1
        )

    if not args.username:
        parser.error(
            "username is required unless --self-test is used."
        )

    try:
        username = get_username(
            args.username
        )

        REPOS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        REPORTS_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        print(
            f"GitGuard scan started for: {username}"
        )

        repos = discover_repositories(
            username
        )

        print(
            f"Repositories discovered: "
            f"{len(repos)}"
        )

        results = []

        for index, repo in enumerate(
            repos,
            start=1,
        ):
            print(
                f"[{index}/{len(repos)}] "
                f"Scanning {repo['name']}..."
            )

            result = scan_repository(
                repo
            )

            results.append(result)

            print(
                f"    Status: "
                f"{result['status']}; "
                f"potential findings: "
                f"{result['finding_count']}"
            )

        report = write_reports(
            username,
            repos,
            results,
        )

        print(
            "\nGitGuard scan complete."
        )

        print(
            "Repositories completed: "
            f"{report['repositories_completed']}"
        )

        print(
            "Repositories failed/incomplete: "
            f"{report['repositories_failed_or_incomplete']}"
        )

        print(
            "Potential findings: "
            f"{report['potential_findings']}"
        )

        print(
            "High risk findings: "
            f"{report['risk_summary']['high']}"
        )

        print(
            "Medium risk findings: "
            f"{report['risk_summary']['medium']}"
        )

        print(
            "Review findings: "
            f"{report['risk_summary']['review']}"
        )

        print(
            "Current approximate matches: "
            f"{report['correlation_summary']['CURRENT_MATCH_APPROXIMATE']}"
        )

        print(
            "Historical-only findings: "
            f"{report['correlation_summary']['HISTORICAL_ONLY']}"
        )

        print(
            "Unknown exposure status: "
            f"{report['correlation_summary']['UNKNOWN']}"
        )

        print(
            f"JSON report: "
            f"{report['json_report']}"
        )

        print(
            f"HTML report: "
            f"{report['html_report']}"
        )

    except KeyboardInterrupt:
        print(
            "\nScan interrupted by user.",
            file=sys.stderr,
        )
        sys.exit(130)

    except (
        ValueError,
        RuntimeError,
    ) as exc:
        print(
            f"Error: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)

    except requests.RequestException as exc:
        print(
            f"GitHub API request failed: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
