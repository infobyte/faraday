"""add running_since to pipeline

Revision ID: 22321da63ce6
Revises: 6d0972a186c8
Create Date: 2026-04-07 12:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '22321da63ce6'
down_revision = '6d0972a186c8'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('pipeline', sa.Column('running_since', sa.DateTime(), nullable=True, server_default=None))


def downgrade():
    op.drop_column('pipeline', 'running_since')
