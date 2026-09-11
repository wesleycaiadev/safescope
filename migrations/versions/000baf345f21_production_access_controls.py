"""production access controls

Revision ID: 000baf345f21
Revises: 20260910_01
Create Date: 2026-09-11 07:39:41.019179
"""

import sqlalchemy as sa
from alembic import op



revision = "000baf345f21"
down_revision = "20260910_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "organization_memberships",
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False, server_default="MEMBER"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('VIEWER', 'MEMBER', 'ADMIN', 'OWNER')", name="ck_membership_role"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("organization_id", "user_id"),
    )
    op.create_index("ix_organization_memberships_user_id", "organization_memberships", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_organization_memberships_user_id", table_name="organization_memberships")
    op.drop_table("organization_memberships")
