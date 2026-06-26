"""Add rollback snapshot protection records."""

from typing import Optional

import sqlalchemy as sa
from alembic import op


revision: str = "0005_rollback_snapshots"
down_revision: Optional[str] = "0004_user_roles"
branch_labels = None
depends_on = None


def _column_names(table_name: str) -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns(table_name)}


def _table_names() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def upgrade() -> None:
    credential_columns = _column_names("credentials")
    if "credential_type" not in credential_columns:
        op.add_column(
            "credentials",
            sa.Column(
                "credential_type",
                sa.String(length=64),
                nullable=False,
                server_default=sa.text("'ssh_private_key'"),
            ),
        )
    if "metadata" not in credential_columns:
        op.add_column(
            "credentials",
            sa.Column(
                "metadata",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'{}'"),
            ),
        )

    if "rollback_snapshots" in _table_names():
        return
    op.create_table(
        "rollback_snapshots",
        sa.Column("id", sa.String(length=96), nullable=False),
        sa.Column("host_id", sa.String(length=96), nullable=False),
        sa.Column("remediation_id", sa.String(length=96), nullable=False),
        sa.Column("provider", sa.String(length=40), nullable=False),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("external_snapshot_id", sa.String(length=255), nullable=True),
        sa.Column("delete_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in (
        "host_id",
        "remediation_id",
        "provider",
        "state",
        "external_snapshot_id",
        "delete_after",
    ):
        op.create_index(
            op.f("ix_rollback_snapshots_%s" % column),
            "rollback_snapshots",
            [column],
            unique=False,
        )


def downgrade() -> None:
    if "rollback_snapshots" in _table_names():
        for column in (
            "delete_after",
            "external_snapshot_id",
            "state",
            "provider",
            "remediation_id",
            "host_id",
        ):
            op.drop_index(
                op.f("ix_rollback_snapshots_%s" % column),
                table_name="rollback_snapshots",
            )
        op.drop_table("rollback_snapshots")

    credential_columns = _column_names("credentials")
    if "metadata" in credential_columns:
        op.drop_column("credentials", "metadata")
    if "credential_type" in credential_columns:
        op.drop_column("credentials", "credential_type")
