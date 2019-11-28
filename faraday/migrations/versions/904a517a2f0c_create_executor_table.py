"""Create Executor table

Revision ID: 904a517a2f0c
Revises: 1dbe9e8e4247
Create Date: 2019-11-05 16:31:27.186749+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '904a517a2f0c'
down_revision = '2a0de6132377'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'executor',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('name', sa.String, nullable=False),
        sa.Column('agent_id', sa.Integer, nullable=False),
        sa.Column('parameters_metadata', sa.JSON, nullable=False, default={}),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer)
    )

    op.create_foreign_key(
        'executor_agent_id_fkey',
        'executor',
        'agent', ['agent_id'], ['id']
    )

    op.create_foreign_key(
        'executor_creator_id_fkey',
        'executor',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'executor_update_user_id_fkey',
        'executor',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.drop_column('agent_schedule', 'agent_id')
    op.execute('DELETE FROM agent_schedule')
    op.add_column('agent_schedule', sa.Column('executor_id', sa.Integer, nullable=False))
    op.add_column('agent_schedule', sa.Column('parameters', sa.JSON, nullable=False, default={}))
    op.create_foreign_key(
        'agent_schedule_executor_id_fkey',
        'agent_schedule',
        'executor', ['executor_id'], ['id']
    )

    op.create_table(
        'agent_execution',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('running', sa.Boolean, nullable=True),
        sa.Column('successful', sa.Boolean, nullable=True),
        sa.Column('message', sa.String, nullable=True),
        sa.Column('executor_id', sa.Integer, nullable=False),
        sa.Column('workspace_id', sa.Integer, nullable=False),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer)

    )

    op.create_foreign_key(
        'agent_execution_executor_id_fkey',
        'agent_execution',
        'executor', ['executor_id'], ['id']
    )

    op.create_foreign_key(
        'agent_execution_workspace_id_fkey',
        'agent_execution',
        'workspace', ['workspace_id'], ['id']
    )

    op.create_foreign_key(
        'agent_execution_creator_id_fkey',
        'agent_execution',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'agent_execution_update_user_id_fkey',
        'agent_execution',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_unique_constraint(
        "uix_executor_table_agent_id_name",
        "executor",
        ["name", "agent_id"]
    )


def downgrade():
    op.add_column('agent_schedule', sa.Column('agent_id', sa.Integer, nullable=False))
    op.create_foreign_key(
        'agent_schedule_agent_id_fkey',
        'agent_schedule',
        'agent', ['agent_id'], ['id']
    )

    op.drop_column('agent_schedule', 'executor_id')
    op.drop_column('agent_schedule', 'parameters')
    op.drop_table('agent_execution')
    op.drop_table('executor')
