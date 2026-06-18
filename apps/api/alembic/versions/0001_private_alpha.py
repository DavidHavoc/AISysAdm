"""Create private alpha control-plane tables."""

from typing import Optional

from alembic import op

from sysadmin_api.database import Base

revision: str = "0001_private_alpha"
down_revision: Optional[str] = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
