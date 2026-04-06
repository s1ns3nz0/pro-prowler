"""SQLite metadata storage for projects and assessment snapshots."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS projects (
    id           TEXT PRIMARY KEY,
    repository   TEXT UNIQUE NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    linked_repos TEXT NOT NULL DEFAULT '[]',
    context_sources TEXT NOT NULL DEFAULT '[]',
    default_branch TEXT NOT NULL DEFAULT 'main',
    terraform_dir TEXT NOT NULL DEFAULT 'infra',
    server_url TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS snapshots (
    id             TEXT PRIMARY KEY,
    project_id     TEXT NOT NULL REFERENCES projects(id),
    commit_hash    TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    plan_hash      TEXT NOT NULL,
    score          INTEGER NOT NULL,
    grade          TEXT NOT NULL,
    finding_count  INTEGER NOT NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count     INTEGER NOT NULL DEFAULT 0,
    gate           TEXT NOT NULL DEFAULT 'pass',
    label          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS audit_trail (
    id                  TEXT PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    snapshot_id         TEXT NOT NULL,
    commit_sha          TEXT NOT NULL DEFAULT '',
    repository          TEXT NOT NULL DEFAULT '',
    changed_resources   TEXT NOT NULL DEFAULT '[]',
    compliance_outcomes TEXT NOT NULL DEFAULT '[]',
    gate_recommendation TEXT NOT NULL DEFAULT 'pass',
    gate_justification  TEXT NOT NULL DEFAULT '',
    agent_version       TEXT NOT NULL DEFAULT '0.1.0'
);

CREATE TABLE IF NOT EXISTS risk_comments (
    id                TEXT PRIMARY KEY,
    project_id        TEXT NOT NULL,
    resource_address  TEXT NOT NULL,
    comment           TEXT NOT NULL DEFAULT '',
    accepted          INTEGER NOT NULL DEFAULT 0,
    expiry_date       TEXT DEFAULT '',
    approver          TEXT DEFAULT '',
    created_at        TEXT NOT NULL,
    snapshot_id       TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS criticality_overrides (
    id                  TEXT PRIMARY KEY,
    project_id          TEXT NOT NULL,
    resource_address    TEXT NOT NULL,
    criticality         TEXT NOT NULL DEFAULT 'MODERATE',
    data_classification TEXT NOT NULL DEFAULT 'internal',
    compliance_scope    TEXT NOT NULL DEFAULT '[]',
    notes               TEXT NOT NULL DEFAULT '',
    updated_by          TEXT DEFAULT '',
    updated_at          TEXT NOT NULL,
    UNIQUE(project_id, resource_address)
);

CREATE TABLE IF NOT EXISTS app_settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS governance_docs (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    doc_type     TEXT NOT NULL DEFAULT 'text',
    filename     TEXT DEFAULT '',
    content_hash TEXT DEFAULT '',
    uploaded_at  TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_snapshots_project ON snapshots(project_id, created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_snapshots_commit ON snapshots(commit_hash)",
    "CREATE INDEX IF NOT EXISTS idx_snapshots_plan_hash ON snapshots(plan_hash)",
    (
        "CREATE INDEX IF NOT EXISTS idx_risk_comments_resource "
        "ON risk_comments(project_id, resource_address)"
    ),
]


@dataclass
class ProjectMeta:
    id: str
    repository: str
    created_at: str
    updated_at: str
    linked_repos: list | None = None
    context_sources: list | None = None
    default_branch: str = "main"
    terraform_dir: str = "infra"
    server_url: str = ""
    artifact_name: str = "terraform-plan"
    workflow_filter: str = ""
    webhook_id: str = ""
    webhook_secret: str = ""
    latest_score: int | None = None
    latest_grade: str | None = None
    snapshot_count: int = 0
    previous_score: int | None = None


@dataclass
class SnapshotMeta:
    id: str
    project_id: str
    commit_hash: str
    created_at: str
    plan_hash: str
    score: int
    grade: str
    finding_count: int
    critical_count: int = 0
    high_count: int = 0
    gate: str = "pass"
    label: str = ""


def _connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: Path) -> None:
    """Create tables and indexes, run migrations."""
    conn = _connect(db_path)
    try:
        conn.executescript(_CREATE_TABLES)
        for idx in _CREATE_INDEXES:
            conn.execute(idx)
        # Migrations for existing databases
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Add columns that may be missing from older databases."""
    columns = {
        r[1] for r in conn.execute("PRAGMA table_info(projects)")
    }
    if "linked_repos" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "linked_repos TEXT NOT NULL DEFAULT '[]'"
        )
    if "context_sources" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "context_sources TEXT NOT NULL DEFAULT '[]'"
        )
    if "default_branch" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "default_branch TEXT NOT NULL DEFAULT 'main'"
        )
    if "terraform_dir" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "terraform_dir TEXT NOT NULL DEFAULT 'infra'"
        )
    if "server_url" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "server_url TEXT NOT NULL DEFAULT ''"
        )
    if "artifact_name" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "artifact_name TEXT NOT NULL DEFAULT 'terraform-plan'"
        )
    if "workflow_filter" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "workflow_filter TEXT NOT NULL DEFAULT ''"
        )
    if "webhook_id" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "webhook_id TEXT NOT NULL DEFAULT ''"
        )
    if "webhook_secret" not in columns:
        conn.execute(
            "ALTER TABLE projects ADD COLUMN "
            "webhook_secret TEXT NOT NULL DEFAULT ''"
        )


# --- Projects ---


def get_or_create_project(
    db_path: Path, repository: str, now: str,
) -> ProjectMeta:
    """Get existing project by repository, or create a new one."""
    import uuid

    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM projects WHERE repository = ?",
            (repository,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE projects SET updated_at = ? WHERE id = ?",
                (now, row["id"]),
            )
            conn.commit()
            return _row_to_project(row)

        project_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO projects (id, repository, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (project_id, repository, now, now),
        )
        conn.commit()
        return ProjectMeta(
            id=project_id,
            repository=repository,
            created_at=now,
            updated_at=now,
        )
    finally:
        conn.close()


def list_projects(db_path: Path) -> list[ProjectMeta]:
    """List all projects with latest score and snapshot count."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM projects ORDER BY updated_at DESC"
        ).fetchall()
        projects = []
        for row in rows:
            p = _row_to_project(row)
            # Get latest two snapshots for trend
            snaps = conn.execute(
                """SELECT score, grade FROM snapshots
                   WHERE project_id = ?
                   ORDER BY created_at DESC LIMIT 2""",
                (p.id,),
            ).fetchall()
            count = conn.execute(
                "SELECT COUNT(*) FROM snapshots WHERE project_id = ?",
                (p.id,),
            ).fetchone()[0]
            p.snapshot_count = count
            if snaps:
                p.latest_score = snaps[0]["score"]
                p.latest_grade = snaps[0]["grade"]
                if len(snaps) > 1:
                    p.previous_score = snaps[1]["score"]
            projects.append(p)
        return projects
    finally:
        conn.close()


def get_project(db_path: Path, project_id: str) -> ProjectMeta | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM projects WHERE id = ?", (project_id,),
        ).fetchone()
        return _row_to_project(row) if row else None
    finally:
        conn.close()


def _row_to_project(row: sqlite3.Row) -> ProjectMeta:
    import json as _json
    keys = row.keys()
    linked_raw = row["linked_repos"] if "linked_repos" in keys else "[]"
    ctx_raw = row["context_sources"] if "context_sources" in keys else "[]"
    try:
        linked = _json.loads(linked_raw) if linked_raw else []
    except (ValueError, TypeError):
        linked = []
    try:
        ctx = _json.loads(ctx_raw) if ctx_raw else []
    except (ValueError, TypeError):
        ctx = []
    return ProjectMeta(
        id=row["id"],
        repository=row["repository"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        linked_repos=linked,
        context_sources=ctx,
        default_branch=row["default_branch"] if "default_branch" in keys else "main",
        terraform_dir=row["terraform_dir"] if "terraform_dir" in keys else "infra",
        server_url=row["server_url"] if "server_url" in keys else "",
        artifact_name=row["artifact_name"] if "artifact_name" in keys else "terraform-plan",
        workflow_filter=row["workflow_filter"] if "workflow_filter" in keys else "",
        webhook_id=row["webhook_id"] if "webhook_id" in keys else "",
        webhook_secret=row["webhook_secret"] if "webhook_secret" in keys else "",
    )


def delete_project(db_path: Path, project_id: str) -> bool:
    """Delete a project and all its snapshots."""
    conn = _connect(db_path)
    try:
        conn.execute(
            "DELETE FROM snapshots WHERE project_id = ?",
            (project_id,),
        )
        conn.execute(
            "DELETE FROM risk_comments WHERE project_id = ?",
            (project_id,),
        )
        conn.execute(
            "DELETE FROM criticality_overrides WHERE project_id = ?",
            (project_id,),
        )
        cursor = conn.execute(
            "DELETE FROM projects WHERE id = ?",
            (project_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


def update_linked_repos(
    db_path: Path, project_id: str, linked_repos: list[str],
) -> None:
    """Update the linked repos for a project."""
    import json as _json
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE projects SET linked_repos = ? WHERE id = ?",
            (_json.dumps(linked_repos), project_id),
        )
        conn.commit()
    finally:
        conn.close()


# --- Snapshots ---


def insert_snapshot(db_path: Path, meta: SnapshotMeta) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO snapshots
               (id, project_id, commit_hash, created_at, plan_hash,
                score, grade, finding_count, critical_count, high_count,
                gate, label)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                meta.id, meta.project_id, meta.commit_hash,
                meta.created_at, meta.plan_hash,
                meta.score, meta.grade, meta.finding_count,
                meta.critical_count, meta.high_count,
                meta.gate, meta.label,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_snapshot(row: sqlite3.Row) -> SnapshotMeta:
    return SnapshotMeta(
        id=row["id"],
        project_id=row["project_id"],
        commit_hash=row["commit_hash"],
        created_at=row["created_at"],
        plan_hash=row["plan_hash"],
        score=row["score"],
        grade=row["grade"],
        finding_count=row["finding_count"],
        critical_count=row["critical_count"],
        high_count=row["high_count"],
        gate=row["gate"],
        label=row["label"],
    )


def get_snapshot(db_path: Path, snapshot_id: str) -> SnapshotMeta | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM snapshots WHERE id = ?", (snapshot_id,),
        ).fetchone()
        return _row_to_snapshot(row) if row else None
    finally:
        conn.close()


def list_snapshots(
    db_path: Path,
    project_id: str | None = None,
    offset: int = 0,
    limit: int = 20,
) -> tuple[list[SnapshotMeta], int]:
    """List snapshots, optionally filtered by project."""
    conn = _connect(db_path)
    try:
        if project_id:
            total = conn.execute(
                "SELECT COUNT(*) FROM snapshots WHERE project_id = ?",
                (project_id,),
            ).fetchone()[0]
            rows = conn.execute(
                """SELECT * FROM snapshots WHERE project_id = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (project_id, limit, offset),
            ).fetchall()
        else:
            total = conn.execute(
                "SELECT COUNT(*) FROM snapshots",
            ).fetchone()[0]
            rows = conn.execute(
                """SELECT * FROM snapshots
                   ORDER BY created_at DESC LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return [_row_to_snapshot(r) for r in rows], total
    finally:
        conn.close()


def get_latest(
    db_path: Path, project_id: str | None = None,
) -> SnapshotMeta | None:
    conn = _connect(db_path)
    try:
        if project_id:
            row = conn.execute(
                """SELECT * FROM snapshots WHERE project_id = ?
                   ORDER BY created_at DESC LIMIT 1""",
                (project_id,),
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM snapshots ORDER BY created_at DESC LIMIT 1",
            ).fetchone()
        return _row_to_snapshot(row) if row else None
    finally:
        conn.close()


def get_previous_for_plan(
    db_path: Path, plan_hash: str, exclude_id: str,
) -> SnapshotMeta | None:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            """SELECT * FROM snapshots
               WHERE plan_hash = ? AND id != ?
               ORDER BY created_at DESC LIMIT 1""",
            (plan_hash, exclude_id),
        ).fetchone()
        return _row_to_snapshot(row) if row else None
    finally:
        conn.close()


def delete_snapshot(db_path: Path, snapshot_id: str) -> bool:
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM snapshots WHERE id = ?", (snapshot_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# --- Audit Trail (append-only) ---


@dataclass
class AuditEntry:
    id: str
    timestamp: str
    snapshot_id: str
    commit_sha: str
    repository: str
    changed_resources: str  # JSON string
    compliance_outcomes: str  # JSON string
    gate_recommendation: str
    gate_justification: str
    agent_version: str = "0.1.0"


def insert_audit_entry(db_path: Path, entry: AuditEntry) -> None:
    """Insert an immutable audit trail entry."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO audit_trail
               (id, timestamp, snapshot_id, commit_sha, repository,
                changed_resources, compliance_outcomes,
                gate_recommendation, gate_justification, agent_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                entry.id, entry.timestamp, entry.snapshot_id,
                entry.commit_sha, entry.repository,
                entry.changed_resources, entry.compliance_outcomes,
                entry.gate_recommendation, entry.gate_justification,
                entry.agent_version,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_audit_entries(
    db_path: Path, snapshot_id: str | None = None, limit: int = 50,
) -> list[AuditEntry]:
    """List audit trail entries, newest first."""
    conn = _connect(db_path)
    try:
        if snapshot_id:
            rows = conn.execute(
                """SELECT * FROM audit_trail
                   WHERE snapshot_id = ?
                   ORDER BY timestamp DESC LIMIT ?""",
                (snapshot_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM audit_trail
                   ORDER BY timestamp DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [
            AuditEntry(
                id=r["id"],
                timestamp=r["timestamp"],
                snapshot_id=r["snapshot_id"],
                commit_sha=r["commit_sha"],
                repository=r["repository"],
                changed_resources=r["changed_resources"],
                compliance_outcomes=r["compliance_outcomes"],
                gate_recommendation=r["gate_recommendation"],
                gate_justification=r["gate_justification"],
                agent_version=r["agent_version"],
            )
            for r in rows
        ]
    finally:
        conn.close()


# --- Risk Comments ---


@dataclass
class RiskComment:
    id: str
    project_id: str
    resource_address: str
    comment: str
    accepted: bool
    expiry_date: str
    approver: str
    created_at: str
    snapshot_id: str = ""


def upsert_risk_comment(db_path: Path, rc: RiskComment) -> None:
    """Insert or update a risk comment for a resource."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO risk_comments
               (id, project_id, resource_address, comment,
                accepted, expiry_date, approver, created_at,
                snapshot_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                 comment=excluded.comment,
                 accepted=excluded.accepted,
                 expiry_date=excluded.expiry_date,
                 approver=excluded.approver""",
            (
                rc.id, rc.project_id, rc.resource_address,
                rc.comment, 1 if rc.accepted else 0,
                rc.expiry_date, rc.approver,
                rc.created_at, rc.snapshot_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_risk_comments(
    db_path: Path, project_id: str,
) -> list[RiskComment]:
    """Get all risk comments for a project."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM risk_comments
               WHERE project_id = ?
               ORDER BY created_at DESC""",
            (project_id,),
        ).fetchall()
        return [_row_to_risk_comment(r) for r in rows]
    finally:
        conn.close()


def get_risk_comments_for_resource(
    db_path: Path, project_id: str, resource_address: str,
) -> list[RiskComment]:
    """Get risk comments for a specific resource."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM risk_comments
               WHERE project_id = ? AND resource_address = ?
               ORDER BY created_at DESC""",
            (project_id, resource_address),
        ).fetchall()
        return [_row_to_risk_comment(r) for r in rows]
    finally:
        conn.close()


def get_active_acceptances(
    db_path: Path, project_id: str, now: str,
) -> dict[str, RiskComment]:
    """Get active (non-expired, accepted) risk comments keyed by resource."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM risk_comments
               WHERE project_id = ? AND accepted = 1
               AND (expiry_date = '' OR expiry_date > ?)
               ORDER BY created_at DESC""",
            (project_id, now),
        ).fetchall()
        result: dict[str, RiskComment] = {}
        for r in rows:
            rc = _row_to_risk_comment(r)
            if rc.resource_address not in result:
                result[rc.resource_address] = rc
        return result
    finally:
        conn.close()


def _row_to_risk_comment(row: sqlite3.Row) -> RiskComment:
    return RiskComment(
        id=row["id"],
        project_id=row["project_id"],
        resource_address=row["resource_address"],
        comment=row["comment"],
        accepted=bool(row["accepted"]),
        expiry_date=row["expiry_date"],
        approver=row["approver"],
        created_at=row["created_at"],
        snapshot_id=row["snapshot_id"],
    )


# --- Criticality Overrides ---


@dataclass
class CriticalityOverride:
    id: str
    project_id: str
    resource_address: str
    criticality: str
    data_classification: str
    compliance_scope: list[str]
    notes: str
    updated_by: str
    updated_at: str


def upsert_criticality_override(
    db_path: Path, override: CriticalityOverride,
) -> None:
    """Insert or update a criticality override."""
    import json as _json
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO criticality_overrides
               (id, project_id, resource_address, criticality,
                data_classification, compliance_scope, notes,
                updated_by, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(project_id, resource_address) DO UPDATE SET
                 criticality=excluded.criticality,
                 data_classification=excluded.data_classification,
                 compliance_scope=excluded.compliance_scope,
                 notes=excluded.notes,
                 updated_by=excluded.updated_by,
                 updated_at=excluded.updated_at""",
            (
                override.id, override.project_id,
                override.resource_address, override.criticality,
                override.data_classification,
                _json.dumps(override.compliance_scope),
                override.notes, override.updated_by,
                override.updated_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_criticality_overrides(
    db_path: Path, project_id: str,
) -> dict[str, CriticalityOverride]:
    """Get all overrides for a project, keyed by resource address."""
    import json as _json
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """SELECT * FROM criticality_overrides
               WHERE project_id = ?""",
            (project_id,),
        ).fetchall()
        result: dict[str, CriticalityOverride] = {}
        for r in rows:
            try:
                scope = _json.loads(r["compliance_scope"])
            except (ValueError, TypeError):
                scope = []
            result[r["resource_address"]] = CriticalityOverride(
                id=r["id"],
                project_id=r["project_id"],
                resource_address=r["resource_address"],
                criticality=r["criticality"],
                data_classification=r["data_classification"],
                compliance_scope=scope,
                notes=r["notes"],
                updated_by=r["updated_by"],
                updated_at=r["updated_at"],
            )
        return result
    finally:
        conn.close()


# --- Governance Documents ---


@dataclass
class GovernanceDoc:
    id: str
    title: str
    doc_type: str  # text, url, pdf, docx
    filename: str
    content_hash: str
    uploaded_at: str
    updated_at: str


def insert_governance_doc(db_path: Path, doc: GovernanceDoc) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            """INSERT INTO governance_docs
               (id, title, doc_type, filename, content_hash,
                uploaded_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                doc.id, doc.title, doc.doc_type, doc.filename,
                doc.content_hash, doc.uploaded_at, doc.updated_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_governance_docs(db_path: Path) -> list[GovernanceDoc]:
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM governance_docs ORDER BY uploaded_at DESC",
        ).fetchall()
        return [
            GovernanceDoc(
                id=r["id"], title=r["title"],
                doc_type=r["doc_type"], filename=r["filename"],
                content_hash=r["content_hash"],
                uploaded_at=r["uploaded_at"],
                updated_at=r["updated_at"],
            )
            for r in rows
        ]
    finally:
        conn.close()


def delete_governance_doc(db_path: Path, doc_id: str) -> bool:
    conn = _connect(db_path)
    try:
        cursor = conn.execute(
            "DELETE FROM governance_docs WHERE id = ?",
            (doc_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# --- App Settings ---

_DEFAULT_SETTINGS: dict[str, str] = {
    "default_criticality": "MODERATE",
    "default_data_classification": "internal",
    "default_compliance_scope": (
        '["PCI_DSS","ISO_27001","ISO_27701","SOC_2","GDPR","ISMS_P"]'
    ),
    "weight_critical": "-15",
    "weight_high": "-8",
    "weight_moderate": "-3",
    "weight_low": "-1",
    "grade_a": "90",
    "grade_b": "75",
    "grade_c": "60",
    "grade_d": "40",
    "risk_critical": "16",
    "risk_high": "9",
    "risk_moderate": "4",
    "risk_low": "2",
    "gate_threshold": "60",
    "server_url": "http://localhost:8000",
}


def get_all_settings(db_path: Path) -> dict[str, str]:
    """Get all settings, filling defaults for missing keys."""
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            "SELECT key, value FROM app_settings",
        ).fetchall()
        saved = {r["key"]: r["value"] for r in rows}
        result = dict(_DEFAULT_SETTINGS)
        result.update(saved)
        return result
    finally:
        conn.close()


def save_settings(
    db_path: Path, settings: dict[str, str],
) -> None:
    """Save multiple settings (upsert)."""
    conn = _connect(db_path)
    try:
        for key, value in settings.items():
            conn.execute(
                """INSERT INTO app_settings (key, value)
                   VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE
                   SET value=excluded.value""",
                (key, str(value)),
            )
        conn.commit()
    finally:
        conn.close()
