"""Create Executor table

Revision ID: 904a517a2f0c
Revises: 1dbe9e8e4247
Create Date: 2019-11-05 16:31:27.186749+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '904a517a2f0c'
down_revision = '1dbe9e8e4247'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'executor',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=False),
        sa.Column('agent_id', sa.Integer, nullable=False),
        sa.Column('parameters_metadata', sa.JSON, nullable=True, default={})
    )

    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id']
    )

    op.add_column('agent_schedule', sa.Column('executor_id', sa.Integer, nullable=True))
    op.add_column('agent_schedule', sa.Column('parameters', sa.JSON, nullable=True, default={}))
    op.create_foreign_key(
        'agent_schedule_executor_id_fkey',
        'agent_schedule',
        'executor', ['executor_id'], ['id']
    )

    op.create_table(
        'agent_execution',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('moment', sa.DateTime, nullable=True),
        sa.Column('agent_id', sa.Integer, nullable=False),
        sa.Column('command_id', sa.Integer, nullable=False)
    )

    op.create_foreign_key(
        'agent_execution_agent_id_fkey',
        'agent_execution',
        'agent', ['agent_id'], ['id']
    )

    op.create_foreign_key(
        'agent_execution_command_id_fkey',
        'agent_execution',
        'command', ['command_id'], ['id']
    )


def downgrade():
    op.drop_column('agent_schedule', 'executor_id')
    op.drop_column('agent_schedule', 'parameters')
    op.drop_table('agent_execution')
    op.drop_table('executor')
