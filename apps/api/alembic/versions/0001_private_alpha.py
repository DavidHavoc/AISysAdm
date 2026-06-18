"""Create private alpha control-plane tables."""

from typing import Optional

from alembic import op

from sysadmin_api.database import Base

revision: str = "0001_private_alpha"
down_revision: Optional[str] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    baseline_tables = [
        table
        for table in Base.metadata.sorted_tables
        if table.name not in {"campaign_hosts"}
    ]
    Base.metadata.create_all(bind=op.get_bind(), tables=baseline_tables)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
