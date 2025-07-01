"""add index for edge case

Revision ID: e2500923d887
Revises: eb9b98d0b4d0
Create Date: 2025-07-01 17:05:38.567553+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'e2500923d887'
down_revision = 'eb9b98d0b4d0'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_execution_run_uuid ON agent_execution (run_uuid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cloud_agent_execution_run_uuid ON cloud_agent_execution (run_uuid)")


def downgrade():
    # Downgrade is handled by 75c38da2da8a
    pass
