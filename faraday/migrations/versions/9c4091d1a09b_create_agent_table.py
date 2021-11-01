"""create agent table

Revision ID: 9c4091d1a09b
Revises: 0d216660da28
Create Date: 2019-05-22 19:17:31.444968+00:00

"""

from alembic import op
import sqlalchemy as sa

revision = '9c4091d1a09b'
down_revision = 'be89aa03e35e'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'agent',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token', sa.Text, nullable=False, unique=True),
        sa.Column('name', sa.Text, nullable=False),
        sa.Column('active', sa.Boolean, nullable=False),
        sa.Column('workspace_id', sa.Integer, nullable=False),
        # metadata
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
    )

    op.create_foreign_key(
        'agent_creator_id_fkey',
        'agent',
        'faraday_user', ['creator_id'], ['id']
    )

    op.create_foreign_key(
        'agent_update_user_id_fkey',
        'agent',
        'faraday_user', ['update_user_id'], ['id']
    )

    op.create_foreign_key(
        'agent_workspace_id_fkey',
        'agent',
        'workspace', ['workspace_id'], ['id']
    )

    op.create_table(
        'agent_schedule',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('description', sa.Text, nullable=False),
        sa.Column('crontab', sa.Text, nullable=False),
        sa.Column('timezone', sa.Text, nullable=False),
        sa.Column('active', sa.Boolean, nullable=False),
        sa.Column('creator_id', sa.Integer),
        sa.Column('update_user_id', sa.Integer),
        sa.Column('create_date', sa.DateTime),
        sa.Column('update_date', sa.DateTime),
        sa.Column('workspace_id', sa.Integer, nullable=False),
        sa.Column('agent_id', sa.Integer, nullable=False),
        sa.Column('last_run', sa.DateTime),
    )

    op.create_foreign_key(
        'agent_schedule_agent_id_fkey',
        'agent_schedule',
        'agent', ['agent_id'], ['id']
    )

    op.create_foreign_key(
        'agent_schedule_id_fkey',
        'agent_schedule',
        'workspace', ['workspace_id'], ['id']
    )


def downgrade():
    op.drop_table('agent_schedule')
    op.drop_table('agent')
