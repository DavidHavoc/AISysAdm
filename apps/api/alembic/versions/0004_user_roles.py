"""Add explicit user roles for alpha authorization policy."""

from typing import Optional

import sqlalchemy as sa
from alembic import op


revision: str = "0004_user_roles"
down_revision: Optional[str] = "0003_durable_job_execution"
branch_labels = None
depends_on = None


def _column_names() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    return {column["name"] for column in inspector.get_columns("users")}


def upgrade() -> None:
    columns = _column_names()
    if "role" not in columns:
        op.add_column(
            "users",
            sa.Column(
                "role",
                sa.String(length=32),
                nullable=False,
                server_default=sa.text("'admin'"),
            ),
        )
    op.execute(sa.text("UPDATE users SET role = 'admin' WHERE role IS NULL OR role = ''"))


def downgrade() -> None:
    columns = _column_names()
    if "role" in columns:
        op.drop_column("users", "role")
