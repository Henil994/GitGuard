import json
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"

st.set_page_config(
    page_title="GitGuard Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ GitGuard Security Dashboard")
st.caption("Secret exposure monitoring, historical scan reports, and persistent scan trends")
st.caption("Reports are loaded from the local reports/ folder on each refresh. Refresh the browser after a new scan.")


def load_reports():
    reports = []
    for path in sorted(REPORTS_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                data["_report_file"] = path.name
                reports.append(data)
        except (OSError, json.JSONDecodeError):
            continue
    return reports


reports = load_reports()

if not reports:
    st.warning(
        "No compatible reports found. Run "
        "`python src/main.py YOUR_GITHUB_USERNAME` first."
    )
    st.stop()

reports.sort(
    key=lambda report: report.get("generated_at_utc", ""),
    reverse=True,
)

labels = [
    f"{r.get('generated_at_utc', 'Unknown')} — {r['_report_file']}"
    for r in reports
]
selected = st.sidebar.selectbox("Scan report", labels)
report = reports[labels.index(selected)]

results = report.get("results", [])
findings = []

for repo in results:
    for finding in repo.get("findings", []):
        findings.append({
            **finding,
            "repository": repo.get("name", "Unknown"),
        })

risk = report.get("risk_summary", {})
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Repositories", report.get("public_non_fork_repositories_discovered", len(results)))
c2.metric("Completed", report.get("repositories_completed", 0))
c3.metric("Potential findings", len(findings))
c4.metric("High risk", risk.get("high", 0))
c5.metric("Failed/incomplete", report.get("repositories_failed_or_incomplete", 0))

st.caption(
    f"Profile: {report.get('profile', 'Unknown')} | "
    f"Generated UTC: {report.get('generated_at_utc', 'Unknown')}"
)

left, right = st.columns(2)

with left:
    st.subheader("Risk distribution")
    st.bar_chart(pd.DataFrame({
        "Risk": ["HIGH", "MEDIUM", "REVIEW"],
        "Findings": [
            risk.get("high", 0),
            risk.get("medium", 0),
            risk.get("review", 0),
        ],
    }).set_index("Risk"))

with right:
    st.subheader("Finding categories")
    categories = report.get("category_summary", {})
    if categories:
        st.bar_chart(pd.DataFrame(
            list(categories.items()),
            columns=["Category", "Findings"],
        ).set_index("Category"))
    else:
        st.info("No category data in this report.")

st.subheader("Repository results")
repo_rows = [{
    "Repository": r.get("name", "Unknown"),
    "Status": r.get("status", "Unknown"),
    "Findings": r.get("finding_count", 0),
    "URL": r.get("url", ""),
    "Note": r.get("note", ""),
} for r in results]

st.dataframe(
    pd.DataFrame(repo_rows),
    width="stretch",
    hide_index=True,
    column_config={
        "URL": st.column_config.LinkColumn("Repository URL")
    },
)

st.subheader("Findings explorer")

if findings:
    df = pd.DataFrame(findings)

    risk_options = sorted(df.get(
        "risk_level", pd.Series(["REVIEW"] * len(df))
    ).fillna("REVIEW").unique().tolist())
    category_options = sorted(df.get(
        "category", pd.Series(["Potential Secret"] * len(df))
    ).fillna("Potential Secret").unique().tolist())
    status_options = sorted(df.get(
        "correlation_status", pd.Series(["UNKNOWN"] * len(df))
    ).fillna("UNKNOWN").unique().tolist())

    a, b, c = st.columns(3)
    with a:
        selected_risks = st.multiselect("Risk", risk_options, default=risk_options)
    with b:
        selected_categories = st.multiselect("Category", category_options, default=category_options)
    with c:
        selected_statuses = st.multiselect("Exposure status", status_options, default=status_options)

    df["risk_level"] = df.get("risk_level", "REVIEW")
    df["category"] = df.get("category", "Potential Secret")
    df["correlation_status"] = df.get("correlation_status", "UNKNOWN")

    filtered = df[
        df["risk_level"].fillna("REVIEW").isin(selected_risks)
        & df["category"].fillna("Potential Secret").isin(selected_categories)
        & df["correlation_status"].fillna("UNKNOWN").isin(selected_statuses)
    ]

    columns = [
        "repository", "rule", "category", "risk_level",
        "risk_score", "file", "line", "commit", "correlation_status",
    ]
    columns = [column for column in columns if column in filtered.columns]
    st.dataframe(filtered[columns], width="stretch", hide_index=True)

    st.download_button(
        "Export filtered findings as CSV",
        filtered[columns].to_csv(index=False).encode("utf-8"),
        file_name="gitguard-findings.csv",
        mime="text/csv",
    )
else:
    st.success("No findings in the selected report.")

st.subheader("Available scan history")
st.dataframe(pd.DataFrame([{
    "Generated UTC": r.get("generated_at_utc", "Unknown"),
    "Profile": r.get("profile", "Unknown"),
    "Repositories": r.get("public_non_fork_repositories_discovered", 0),
    "Completed": r.get("repositories_completed", 0),
    "Findings": r.get("potential_findings", 0),
    "Report": r.get("_report_file", ""),
} for r in reports]), width="stretch", hide_index=True)

with st.expander("Limitations and safe use"):
    for item in report.get("limitations", []):
        st.write(f"- {item}")
    st.write(
        "Risk scores are heuristic, not CVSS. Exposure correlation is "
        "approximate and cannot establish whether a credential is valid "
        "or revoked. Do not import raw reports containing secret values."
    )


# Persistent scan history (Phase 2)
st.divider()
st.header("Persistent scan history")
try:
    import sys
    if str(ROOT / "src") not in sys.path:
        sys.path.insert(0, str(ROOT / "src"))
    from history import history as load_history
    historical_scans = load_history()
    if historical_scans:
        history_df = pd.DataFrame(historical_scans)
        st.caption("SQLite stores normalized finding metadata only, never detected secret values.")
        st.dataframe(history_df, width="stretch", hide_index=True)
        st.line_chart(history_df.sort_values("id").set_index("generated_at_utc")[["potential_findings", "high_risk"]], width="stretch")
    else:
        st.info("No database history yet. Run a scan with `python src/main.py USERNAME` to record the first scan.")
except (OSError, ValueError, RuntimeError) as exc:
    st.warning(f"Could not load persistent scan history: {exc}")
