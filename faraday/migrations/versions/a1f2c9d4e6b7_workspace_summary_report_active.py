"""workspace summary report active flag

Revision ID: a1f2c9d4e6b7
Revises: 59bf674e5b99
Create Date: 2026-08-05 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = 'a1f2c9d4e6b7'
down_revision = '59bf674e5b99'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'workspace_summary_report',
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('true')),
    )


def downgrade():
    op.drop_column('workspace_summary_report', 'active')
