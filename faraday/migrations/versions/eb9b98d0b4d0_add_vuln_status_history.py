"""add vuln status history

Revision ID: eb9b98d0b4d0
Revises: 293724cb146d
Create Date: 2025-03-17 17:31:10.488451+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'eb9b98d0b4d0'
down_revision = 'a29d52685b58'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('vulnerability_status_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('open', 'closed', 're-opened', 'risk-accepted', name='vulnerability_status_history_statuses'), nullable=False),
    sa.Column('change_date', sa.DateTime(), nullable=True, server_default=sa.text('now()')),
    sa.Column('vulnerability_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['vulnerability_id'], ['vulnerability.id'], ondelete="CASCADE"),
    sa.ForeignKeyConstraint(['user_id'], ['faraday_user.id'], ondelete="SET NULL"),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_vulnerability_status_history_vulnerability_id'), 'vulnerability_status_history', ['vulnerability_id'], unique=False)
    op.create_index(op.f('ix_vulnerability_status_history_change_date'), 'vulnerability_status_history', ['change_date'], unique=False)
    op.create_index(op.f('ix_user_id_vulnerability_status_history'), 'vulnerability_status_history', ['user_id'], unique=False)

    op.create_index('ix_vulnerability_status_history_vuln_status', 'vulnerability_status_history', ['vulnerability_id', 'status'], unique=False)


def downgrade():
    op.drop_index('ix_vulnerability_status_history_vuln_status', table_name='vulnerability_status_history')
    op.drop_index(op.f('ix_vulnerability_status_history_change_date'), table_name='vulnerability_status_history')
    op.drop_index(op.f('ix_vulnerability_status_history_vulnerability_id'), table_name='vulnerability_status_history')
    op.drop_index(op.f('ix_user_id_vulnerability_status_history'), table_name='vulnerability_status_history')
    op.drop_table('vulnerability_status_history')
    op.execute("DROP TYPE vulnerability_status_history_statuses")
