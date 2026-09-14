"""remove is_preview

Revision ID: a94bf314d524
Revises: 1c0d3377b5cc
Create Date: 2026-04-08 15:52:33.048551+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a94bf314d524'
down_revision = '1c0d3377b5cc'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('executive_report', 'is_preview')


def downgrade():
    op.add_column('executive_report', sa.Column('is_preview', sa.BOOLEAN(), server_default=sa.text('false'), autoincrement=False, nullable=False))
