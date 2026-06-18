"""Add durable per-host campaign plan bindings."""

from typing import Optional

import sqlalchemy as sa
from alembic import op

revision: str = "0002_campaign_host_plans"
down_revision: Optional[str] = "0001_private_alpha"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "campaign_hosts" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "campaign_hosts",
        sa.Column("id", sa.String(length=196), nullable=False),
        sa.Column("campaign_id", sa.String(length=96), nullable=False),
        sa.Column("host_id", sa.String(length=96), nullable=False),
        sa.Column("remediation_id", sa.String(length=96), nullable=True),
        sa.Column("state", sa.String(length=40), nullable=False),
        sa.Column("approval_state", sa.String(length=40), nullable=False),
        sa.Column("reboot_approval_state", sa.String(length=40), nullable=False),
        sa.Column("plan_version", sa.Integer(), nullable=True),
        sa.Column("plan_hash", sa.String(length=64), nullable=True),
        sa.Column("job_id", sa.String(length=96), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "host_id",
            name="uq_campaign_host_campaign_host",
        ),
    )
    op.create_index(
        op.f("ix_campaign_hosts_campaign_id"),
        "campaign_hosts",
        ["campaign_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_host_id"),
        "campaign_hosts",
        ["host_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_remediation_id"),
        "campaign_hosts",
        ["remediation_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_state"),
        "campaign_hosts",
        ["state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_approval_state"),
        "campaign_hosts",
        ["approval_state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_reboot_approval_state"),
        "campaign_hosts",
        ["reboot_approval_state"],
        unique=False,
    )
    op.create_index(
        op.f("ix_campaign_hosts_job_id"),
        "campaign_hosts",
        ["job_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_campaign_hosts_job_id"), table_name="campaign_hosts")
    op.drop_index(
        op.f("ix_campaign_hosts_reboot_approval_state"),
        table_name="campaign_hosts",
    )
    op.drop_index(
        op.f("ix_campaign_hosts_approval_state"),
        table_name="campaign_hosts",
    )
    op.drop_index(op.f("ix_campaign_hosts_state"), table_name="campaign_hosts")
    op.drop_index(
        op.f("ix_campaign_hosts_remediation_id"),
        table_name="campaign_hosts",
    )
    op.drop_index(op.f("ix_campaign_hosts_host_id"), table_name="campaign_hosts")
    op.drop_index(
        op.f("ix_campaign_hosts_campaign_id"),
        table_name="campaign_hosts",
    )
    op.drop_table("campaign_hosts")
