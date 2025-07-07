"""workspace summary report

Revision ID: 2063ac75ffb1
Revises: 45a831782601
Create Date: 2025-05-22 19:58:33.565693+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = '2063ac75ffb1'
down_revision = '45a831782601'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE TYPE summary_period_types AS ENUM  ('daily', 'weekly', 'monthly', 'yearly')")
    op.create_table('workspace_summary_report',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('recipients', JSONType(), nullable=False),
    sa.Column(
        'summary_period_type',
        sa.Enum('daily', 'weekly', 'monthly', 'yearly', name='summary_period_types'),
        default='weekly',
        nullable=False,
    ),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['faraday_user.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('creator_id', 'workspace_id', name='uix_workspace_summary_report_creator_workspace')
    )
    op.create_index(op.f('ix_workspace_summary_report_workspace_id'), 'workspace_summary_report', ['workspace_id'], unique=False)
    op.create_index(op.f('ix_workspace_summary_report_user_id'), 'workspace_summary_report', ['user_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_workspace_summary_report_user_id'), table_name='workspace_summary_report')
    op.drop_index(op.f('ix_workspace_summary_report_workspace_id'), table_name='workspace_summary_report')
    op.drop_table('workspace_summary_report')
    op.execute("DROP TYPE summary_period_types")
