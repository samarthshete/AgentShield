from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from agentshield.models.finding import Finding
from agentshield.models.scan import ScanRun
from agentshield.models.target import ScannedTarget

if TYPE_CHECKING:
    from agentshield.models.dynamic import DynamicScanResult


def _ensure_columns(conn: sqlite3.Connection, table: str, column_defs: dict[str, str]) -> None:
    cur = conn.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    for name, col_sql in column_defs.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {col_sql}")


def init_sqlite(db_path: str | Path) -> None:
    """Create all tables (Phase 1 + dynamic) and add any missing columns."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id TEXT PRIMARY KEY,
            target_path TEXT NOT NULL,
            mode TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT,
            duration_ms INTEGER,
            findings_count INTEGER DEFAULT 0,
            high_or_critical_count INTEGER DEFAULT 0,
            overall_risk_score INTEGER DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_run_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT,
            affected_component TEXT,
            recommendation TEXT,
            rule_id TEXT,
            is_confirmed INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scanned_targets (
            id TEXT PRIMARY KEY,
            scan_run_id TEXT NOT NULL,
            target_name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            target_kind TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS dynamic_scan_runs (
            id TEXT PRIMARY KEY,
            scenario_id TEXT NOT NULL,
            scenario_name TEXT NOT NULL,
            category TEXT NOT NULL,
            ran_at TEXT NOT NULL,
            violation_count INTEGER DEFAULT 0,
            max_severity TEXT,
            passed_clean INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS policy_violations (
            id TEXT PRIMARY KEY,
            dynamic_run_id TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            evidence TEXT,
            step_seq INTEGER,
            recommendation TEXT
        )
        """
    )
    conn.commit()

    _ensure_columns(
        conn,
        "scan_runs",
        {
            "started_at": "TEXT NOT NULL DEFAULT ''",
            "completed_at": "TEXT",
            "duration_ms": "INTEGER",
            "findings_count": "INTEGER DEFAULT 0",
            "high_or_critical_count": "INTEGER DEFAULT 0",
            "overall_risk_score": "INTEGER DEFAULT 0",
        },
    )
    _ensure_columns(
        conn,
        "findings",
        {
            "affected_component": "TEXT",
            "recommendation": "TEXT",
            "rule_id": "TEXT",
            "is_confirmed": "INTEGER NOT NULL DEFAULT 0",
        },
    )

    conn.commit()
    conn.close()


def persist_scan(
    db_path: str | Path,
    scan_run: ScanRun,
    findings: list[Finding],
    targets: list[ScannedTarget],
) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO scan_runs (
            id, target_path, mode, started_at, completed_at, duration_ms,
            findings_count, high_or_critical_count, overall_risk_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_run.id,
            scan_run.target_path,
            scan_run.mode,
            scan_run.started_at,
            scan_run.completed_at,
            scan_run.duration_ms,
            scan_run.findings_count,
            scan_run.high_or_critical_count,
            scan_run.overall_risk_score,
        ),
    )
    for t in targets:
        cur.execute(
            """
            INSERT INTO scanned_targets (id, scan_run_id, target_name, target_path, target_kind)
            VALUES (?, ?, ?, ?, ?)
            """,
            (t.id, t.scan_run_id, t.target_name, t.target_path, t.target_kind),
        )
    for f in findings:
        cur.execute(
            """
            INSERT INTO findings (
                id, scan_run_id, category, severity, title, evidence,
                affected_component, recommendation, rule_id, is_confirmed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f.id,
                scan_run.id,
                f.category,
                f.severity,
                f.title,
                f.evidence,
                f.affected_component,
                f.recommendation,
                f.rule_id,
                1 if f.is_confirmed else 0,
            ),
        )
    conn.commit()
    conn.close()


def persist_dynamic_scan(
    db_path: str | Path,
    run_id: str,
    result: DynamicScanResult,
    ran_at: str,
) -> None:
    import uuid as _uuid

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO dynamic_scan_runs (
            id, scenario_id, scenario_name, category, ran_at,
            violation_count, max_severity, passed_clean
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            result.scenario_id,
            result.scenario_name,
            result.category,
            ran_at,
            result.violation_count,
            result.max_severity,
            1 if result.passed_clean else 0,
        ),
    )
    for v in result.violations:
        cur.execute(
            """
            INSERT INTO policy_violations (
                id, dynamic_run_id, policy_id, category, severity,
                title, evidence, step_seq, recommendation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _uuid.uuid4().hex,
                run_id,
                v.policy_id,
                v.category,
                v.severity,
                v.title,
                v.evidence,
                v.step_seq,
                v.recommendation,
            ),
        )
    conn.commit()
    conn.close()
