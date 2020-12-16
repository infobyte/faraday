"""Add command_id to Agent Execution

Revision ID: 5658775e113f
Revises: e03a13c41a67
Create Date: 2020-12-07 22:21:28.005670+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5658775e113f'
down_revision = 'e03a13c41a67'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'agent_execution',
        sa.Column('command_id', sa.Integer),
    )
    op.create_foreign_key(
        'agent_execution_command_id_fkey',
        'agent_execution',
        'command',
        ['command_id'],
        ['id'],
    )


def downgrade():
    op.drop_constraint('agent_execution_command_id_fkey', 'agent_execution')
    op.drop_column('agent_execution', 'command_id')
