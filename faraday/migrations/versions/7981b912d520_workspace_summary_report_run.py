"""workspace summary report run

Revision ID: 7981b912d520
Revises: 2b45cf202f3f
Create Date: 2026-07-31 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '7981b912d520'
down_revision = '2b45cf202f3f'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('workspace_summary_report_run',
        sa.Column('create_date', sa.DateTime(), nullable=True),
        sa.Column('update_date', sa.DateTime(), nullable=True),
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('workspace_summary_report_id', sa.Integer(), nullable=False),
        sa.Column('filename', sa.Text(), nullable=False),
        sa.Column('creator_id', sa.Integer(), nullable=True),
        sa.Column('update_user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['workspace_summary_report_id'], ['workspace_summary_report.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_workspace_summary_report_run_workspace_summary_report_id'),
        'workspace_summary_report_run',
        ['workspace_summary_report_id'],
        unique=False,
    )
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE object_types ADD VALUE IF NOT EXISTS 'ws_sum_report'")


def downgrade():
    op.execute("DELETE FROM file WHERE object_type = 'ws_sum_report'")
    op.drop_index(
        op.f('ix_workspace_summary_report_run_workspace_summary_report_id'),
        table_name='workspace_summary_report_run',
    )
    op.drop_table('workspace_summary_report_run')
