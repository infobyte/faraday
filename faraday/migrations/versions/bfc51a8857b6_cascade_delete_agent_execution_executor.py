"""add cascade delete to agent_execution executor fk

Revision ID: bfc51a8857b6
Revises: 4000d08195fc
Create Date: 2026-07-21 17:25:00.000000+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'bfc51a8857b6'
down_revision = '4000d08195fc'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('agent_execution_executor_id_fkey', 'agent_execution', type_='foreignkey')
    op.create_foreign_key(
        'agent_execution_executor_id_fkey',
        'agent_execution',
        'executor', ['executor_id'], ['id'],
        ondelete='CASCADE'
    )


def downgrade():
    op.drop_constraint('agent_execution_executor_id_fkey', 'agent_execution', type_='foreignkey')
    op.create_foreign_key(
        'agent_execution_executor_id_fkey',
        'agent_execution',
        'executor', ['executor_id'], ['id']
    )
