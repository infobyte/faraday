"""add target to action

Revision ID: 11560f56f480
Revises: f7ca45632cce
Create Date: 2024-04-05 18:38:29.002319+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '11560f56f480'
down_revision = 'f7ca45632cce'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'action', sa.Column('target', sa.String(length=255), nullable=True, server_default='')
    )


def downgrade():
    op.drop_column('action', 'target')
