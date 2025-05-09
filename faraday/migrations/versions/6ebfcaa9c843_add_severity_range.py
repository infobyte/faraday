"""add severity range

Revision ID: 6ebfcaa9c843
Revises: 39ddd3ca3a20
Create Date: 2025-05-09 19:57:50.713596+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6ebfcaa9c843'
down_revision = '39ddd3ca3a20'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('agent_schedule', sa.Column('min_severity', sa.String(), nullable=True))
    op.add_column('agent_schedule', sa.Column('max_severity', sa.String(), nullable=True))


def downgrade():
    op.drop_column('agent_schedule', 'max_severity')
    op.drop_column('agent_schedule', 'min_severity')
