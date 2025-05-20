"""weekly report

Revision ID: 8fc339bc492e
Revises: 75c38da2da8a
Create Date: 2025-05-20 17:00:06.446162+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = '8fc339bc492e'
down_revision = '75c38da2da8a'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('weekly_report',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('recipients', JSONType(), nullable=False),
    sa.Column('crontab', sa.Text(), nullable=False),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('creator_id', 'workspace_id', name='uix_weekly_report_creator_workspace')
    )
    op.create_index(op.f('ix_weekly_report_workspace_id'), 'weekly_report', ['workspace_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_weekly_report_workspace_id'), table_name='weekly_report')
    op.drop_table('weekly_report')
