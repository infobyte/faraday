"""workspace summary report

Revision ID: 2063ac75ffb1
Revises: 75c38da2da8a
Create Date: 2025-05-22 19:58:33.565693+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = '2063ac75ffb1'
down_revision = '75c38da2da8a'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE TYPE report_schedule_types AS ENUM  ('daily', 'weekly', 'monthly', 'yearly')")
    op.create_table('workspace_summary_report',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('recipients', JSONType(), nullable=False),
    sa.Column(
        'report_schedule_type',
        sa.Enum('daily', 'weekly', 'monthly', 'yearly', name='schedule_types'),
        default='weekly',
        nullable=False,
    ),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('creator_id', 'workspace_id', name='uix_workspace_summary_report_creator_workspace')
    )
    op.create_index(op.f('ix_workspace_summary_report_workspace_id'), 'workspace_summary_report', ['workspace_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_workspace_summary_report_workspace_id'), table_name='workspace_summary_report')
    op.drop_table('workspace_summary_report')
    op.execute("DROP TYPE report_schedule_types")
