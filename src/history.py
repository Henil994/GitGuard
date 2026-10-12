"""Persistent, secret-safe scan history for GitGuard."""
from __future__ import annotations
import hashlib
import json
import os
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB = ROOT / "data" / "gitguard.db"

def _connect(db_path=None):
    path = Path(db_path or os.environ.get("GITGUARD_DB_PATH", DEFAULT_DB))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    conn = sqlite3.connect(path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def initialize(db_path=None):
    with _connect(db_path) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          profile TEXT NOT NULL,
          generated_at_utc TEXT NOT NULL,
          repositories_discovered INTEGER NOT NULL DEFAULT 0,
          repositories_completed INTEGER NOT NULL DEFAULT 0,
          potential_findings INTEGER NOT NULL DEFAULT 0,
          high_risk INTEGER NOT NULL DEFAULT 0,
          report_file TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          fingerprint TEXT NOT NULL,
          repository TEXT NOT NULL,
          rule TEXT NOT NULL,
          category TEXT NOT NULL,
          risk_level TEXT NOT NULL,
          risk_score INTEGER NOT NULL,
          file_path TEXT NOT NULL,
          correlation_status TEXT NOT NULL,
          UNIQUE(scan_id, fingerprint)
        );
        CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
        CREATE INDEX IF NOT EXISTS idx_scans_profile_time ON scans(profile, generated_at_utc);
        """)

def _safe_finding(repo_name, finding):
    # Persist metadata only. Secret, Match, raw, and arbitrary fields are never stored.
    fields = {
        "repository": str(repo_name)[:200],
        "rule": str(finding.get("rule", "unknown"))[:100],
        "category": str(finding.get("category", "Potential Secret"))[:100],
        "risk_level": str(finding.get("risk", {}).get("level", finding.get("risk_level", "REVIEW")))[:20],
        "risk_score": int(finding.get("risk", {}).get("score", finding.get("risk_score", 0)) or 0),
        "file_path": str(finding.get("file", "unknown"))[:1000],
        "correlation_status": str(finding.get("correlation_status", "UNKNOWN"))[:50],
    }
    # Stable metadata fingerprint, deliberately excluding secret values and line contents.
    identity = "\0".join((fields["repository"], fields["rule"], fields["category"], fields["file_path"]))
    fields["fingerprint"] = hashlib.sha256(identity.encode("utf-8", "replace")).hexdigest()
    return fields

def record_report(report, report_file=None, db_path=None):
    """Persist safe metadata and return counts for new/resolved/recurring findings."""
    initialize(db_path)
    profile = str(report.get("profile", "unknown"))[:200]
    generated = str(report.get("generated_at_utc") or datetime.now(timezone.utc).isoformat())
    safe_rows = []
    for repo in report.get("results", []):
        if not isinstance(repo, dict):
            continue
        name = str(repo.get("name", "unknown"))
        for finding in repo.get("findings", []):
            if isinstance(finding, dict):
                safe_rows.append(_safe_finding(name, finding))
    with _connect(db_path) as conn:
        previous = conn.execute(
            "SELECT id FROM scans WHERE profile=? ORDER BY id DESC LIMIT 1", (profile,)
        ).fetchone()
        previous_ids = set()
        if previous:
            previous_ids = {r[0] for r in conn.execute(
                "SELECT fingerprint FROM findings WHERE scan_id=?", (previous["id"],)
            )}
        scan_cur = conn.execute(
            """INSERT INTO scans(profile, generated_at_utc, repositories_discovered,
               repositories_completed, potential_findings, high_risk, report_file)
               VALUES(?,?,?,?,?,?,?)""",
            (profile, generated,
             int(report.get("public_non_fork_repositories_discovered", len(report.get("results", []))) or 0),
             int(report.get("repositories_completed", 0) or 0),
             len(safe_rows), int((report.get("risk_summary") or {}).get("high", 0) or 0),
             str(report_file or "")[:1000])
        )
        scan_id = scan_cur.lastrowid
        for row in safe_rows:
            conn.execute(
                """INSERT OR IGNORE INTO findings
                   (scan_id,fingerprint,repository,rule,category,risk_level,risk_score,file_path,correlation_status)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (scan_id,row["fingerprint"],row["repository"],row["rule"],row["category"],
                 row["risk_level"],row["risk_score"],row["file_path"],row["correlation_status"])
            )
        current_ids = {r["fingerprint"] for r in safe_rows}
        return {
            "scan_id": scan_id,
            "new": len(current_ids - previous_ids),
            "resolved": len(previous_ids - current_ids) if previous else 0,
            "recurring": len(current_ids & previous_ids),
            "findings": len(current_ids),
        }

def history(db_path=None, limit=50):
    initialize(db_path)
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (max(1, min(int(limit), 500)),)
        )]

def findings_for_scan(scan_id, db_path=None):
    initialize(db_path)
    with _connect(db_path) as conn:
        return [dict(r) for r in conn.execute(
            "SELECT repository,rule,category,risk_level,risk_score,file_path,correlation_status "
            "FROM findings WHERE scan_id=? ORDER BY risk_score DESC", (int(scan_id),)
        )]
