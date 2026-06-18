"""Add durable job execution leases and failure metadata."""

from typing import Optional

import sqlalchemy as sa
from alembic import op


revision: str = "0003_durable_job_execution"
down_revision: Optional[str] = "0002_campaign_host_plans"
branch_labels = None
depends_on = None


def _column_names() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns("jobs")}


def _index_names() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {index["name"] for index in inspector.get_indexes("jobs")}


def upgrade() -> None:
    columns = _column_names()
    additions = [
        ("lease_owner", sa.Column("lease_owner", sa.String(length=255), nullable=True)),
        (
            "lease_expires_at",
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        ),
        (
            "heartbeat_at",
            sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        ),
        (
            "attempts",
            sa.Column(
                "attempts",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            ),
        ),
        ("last_failure", sa.Column("last_failure", sa.JSON(), nullable=True)),
    ]
    for name, column in additions:
        if name not in columns:
            op.add_column("jobs", column)

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(
            sa.text(
                "UPDATE jobs "
                "SET attempts = COALESCE((payload ->> 'attempts')::integer, 0)"
            )
        )
    elif bind.dialect.name == "sqlite":
        op.execute(
            sa.text(
                "UPDATE jobs "
                "SET attempts = COALESCE(json_extract(payload, '$.attempts'), 0)"
            )
        )

    indexes = _index_names()
    if "ix_jobs_lease_owner" not in indexes:
        op.create_index("ix_jobs_lease_owner", "jobs", ["lease_owner"], unique=False)
    if "ix_jobs_lease_expires_at" not in indexes:
        op.create_index(
            "ix_jobs_lease_expires_at",
            "jobs",
            ["lease_expires_at"],
            unique=False,
        )


def downgrade() -> None:
    indexes = _index_names()
    if "ix_jobs_lease_expires_at" in indexes:
        op.drop_index("ix_jobs_lease_expires_at", table_name="jobs")
    if "ix_jobs_lease_owner" in indexes:
        op.drop_index("ix_jobs_lease_owner", table_name="jobs")

    columns = _column_names()
    for name in (
        "last_failure",
        "attempts",
        "heartbeat_at",
        "lease_expires_at",
        "lease_owner",
    ):
        if name in columns:
            op.drop_column("jobs", name)
