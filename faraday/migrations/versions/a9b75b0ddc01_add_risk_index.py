"""add risk index

Revision ID: a9b75b0ddc01
Revises: 6bbf0b0120cf
Create Date: 2026-04-09 12:57:42.408870+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a9b75b0ddc01'
down_revision = '6bbf0b0120cf'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY ix_vulnerability_workspace_id_risk "
            "ON vulnerability (workspace_id) INCLUDE (risk)"
        )


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS ix_vulnerability_workspace_id_risk"
        )
