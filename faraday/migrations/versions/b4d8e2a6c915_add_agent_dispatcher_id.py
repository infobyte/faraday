"""add dispatcher_id to agent

Revision ID: b4d8e2a6c915
Revises: c7e41d9a2b58
Create Date: 2026-11-02 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b4d8e2a6c915'
down_revision = 'c7e41d9a2b58'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('agent', sa.Column('dispatcher_id', sa.String(22), nullable=True, unique=True))


def downgrade():
    op.drop_column('agent', 'dispatcher_id')
