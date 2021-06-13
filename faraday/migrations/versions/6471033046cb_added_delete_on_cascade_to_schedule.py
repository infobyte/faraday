"""Added delete on cascade to schedule

Revision ID: 6471033046cb
Revises: d3afdb4e0b11
Create Date: 2021-02-09 13:19:45.393841+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '6471033046cb'
down_revision = 'd3afdb4e0b11'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint('executor_agent_id_fkey', 'executor')
    op.drop_constraint('agent_schedule_executor_id_fkey', 'agent_schedule')

    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id'],
        ondelete='CASCADE'
    )

    op.create_foreign_key(
        'agent_schedule_executor_id_fkey',
        'agent_schedule',
        'executor', ['executor_id'], ['id'],
        ondelete='CASCADE'
    )


def downgrade():
    op.drop_constraint('executor_agent_id_fkey', 'executor')
    op.drop_constraint('agent_schedule_executor_id_fkey', 'agent_schedule')

    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id']
    )

    op.create_foreign_key(
        'agent_schedule_executor_id_fkey',
        'agent_schedule',
        'executor', ['executor_id'], ['id']
    )
