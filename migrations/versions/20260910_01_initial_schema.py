"""Frozen initial schema: later model changes must use new revisions."""

import sqlalchemy as sa
from alembic import op

revision = "20260910_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_projects_organization_id"), "projects", ["organization_id"], unique=False)
    op.create_table(
        "targets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("base_url", sa.String(length=2048), nullable=False),
        sa.Column("root_domain", sa.String(length=255), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("base_url"),
    )
    op.create_index(op.f("ix_targets_project_id"), "targets", ["project_id"], unique=False)
    op.create_index(op.f("ix_targets_root_domain"), "targets", ["root_domain"], unique=False)
    op.create_table(
        "authorizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("representative_name", sa.String(length=200), nullable=False),
        sa.Column("representative_email", sa.String(length=320), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active_testing", sa.Boolean(), nullable=False),
        sa.Column("allow_mutations", sa.Boolean(), nullable=False),
        sa.Column("allowed_verbs", sa.JSON(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("max_rps", sa.Float(), nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_authorizations_target_id"), "authorizations", ["target_id"], unique=False)
    op.create_table(
        "domain_verifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("method", sa.String(length=32), nullable=False),
        sa.Column("token_digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest"),
    )
    op.create_index(op.f("ix_domain_verifications_target_id"), "domain_verifications", ["target_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_findings_target_id"), "findings", ["target_id"], unique=False)
    op.create_table(
        "scopes",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("origin", sa.String(length=512), nullable=False),
        sa.Column("is_excluded", sa.Boolean(), nullable=False),
        sa.Column("path_pattern", sa.String(length=2048), nullable=True),
        sa.Column("allowed_verbs", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scopes_target_id"), "scopes", ["target_id"], unique=False)
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("actor", sa.String(length=200), nullable=False),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("authorization_id", sa.String(length=36), nullable=True),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id"],
            ["authorizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_audit_logs_authorization_id"), "audit_logs", ["authorization_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_organization_id"), "audit_logs", ["organization_id"], unique=False)
    op.create_index(op.f("ix_audit_logs_target_id"), "audit_logs", ["target_id"], unique=False)
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target_id", sa.String(length=36), nullable=False),
        sa.Column("authorization_id", sa.String(length=36), nullable=True),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("policy_snapshot", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorization_id"],
            ["authorizations.id"],
        ),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_scan_jobs_authorization_id"), "scan_jobs", ["authorization_id"], unique=False)
    op.create_index(op.f("ix_scan_jobs_target_id"), "scan_jobs", ["target_id"], unique=False)
    op.create_table(
        "scan_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("worker_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["scan_jobs.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("scan_run_id", sa.String(length=36), nullable=False),
        sa.Column("source", sa.String(length=100), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("sanitized_data", sa.JSON(), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
        ),
        sa.ForeignKeyConstraint(
            ["scan_run_id"],
            ["scan_runs.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_evidence_finding_id"), "evidence", ["finding_id"], unique=False)
    op.create_index(op.f("ix_evidence_scan_run_id"), "evidence", ["scan_run_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_evidence_scan_run_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_finding_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_table("scan_runs")
    op.drop_index(op.f("ix_scan_jobs_target_id"), table_name="scan_jobs")
    op.drop_index(op.f("ix_scan_jobs_authorization_id"), table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index(op.f("ix_audit_logs_target_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_organization_id"), table_name="audit_logs")
    op.drop_index(op.f("ix_audit_logs_authorization_id"), table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index(op.f("ix_scopes_target_id"), table_name="scopes")
    op.drop_table("scopes")
    op.drop_index(op.f("ix_findings_target_id"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_domain_verifications_target_id"), table_name="domain_verifications")
    op.drop_table("domain_verifications")
    op.drop_index(op.f("ix_authorizations_target_id"), table_name="authorizations")
    op.drop_table("authorizations")
    op.drop_index(op.f("ix_targets_root_domain"), table_name="targets")
    op.drop_index(op.f("ix_targets_project_id"), table_name="targets")
    op.drop_table("targets")
    op.drop_index(op.f("ix_projects_organization_id"), table_name="projects")
    op.drop_table("projects")
    op.drop_table("organizations")
