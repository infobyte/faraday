"""cloud_agents

Revision ID: 9f826327658a
Revises: 11560f56f480
Create Date: 2022-05-10 13:45:50.704145+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType


# revision identifiers, used by Alembic.
revision = '9f826327658a'
down_revision = '11560f56f480'
branch_labels = None
depends_on = None


def upgrade():
    if not op.get_context().as_sql:
        op.get_bind()
    op.create_table('cloud_agent',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('slug', sa.String(), nullable=False),
    sa.Column('access_token', sa.Text(), nullable=True),
    sa.Column('params', JSONType(), nullable=True),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('access_token'),
    sa.UniqueConstraint('slug')
    )
    op.create_table('cloud_agent_execution',
    sa.Column('create_date', sa.DateTime(), nullable=True),
    sa.Column('update_date', sa.DateTime(), nullable=True),
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('running', sa.Boolean(), nullable=True),
    sa.Column('successful', sa.Boolean(), nullable=True),
    sa.Column('message', sa.String(), nullable=True),
    sa.Column('cloud_agent_id', sa.Integer(), nullable=False),
    sa.Column('workspace_id', sa.Integer(), nullable=False),
    sa.Column('parameters_data', JSONType(), nullable=False),
    sa.Column('command_id', sa.Integer(), nullable=True),
    sa.Column('creator_id', sa.Integer(), nullable=True),
    sa.Column('update_user_id', sa.Integer(), nullable=True),
    sa.Column('last_run', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['cloud_agent_id'], ['cloud_agent.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['command_id'], ['command.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['creator_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['update_user_id'], ['faraday_user.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['workspace_id'], ['workspace.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_cloud_agent_execution_cloud_agent_id'), 'cloud_agent_execution', ['cloud_agent_id'], unique=False)
    op.create_index(op.f('ix_cloud_agent_execution_command_id'), 'cloud_agent_execution', ['command_id'], unique=False)
    op.create_index(op.f('ix_cloud_agent_execution_workspace_id'), 'cloud_agent_execution', ['workspace_id'], unique=False)
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE import_source_enum ADD VALUE IF NOT EXISTS 'cloud_agent'")


def downgrade():
    op.execute("DELETE FROM command WHERE import_source = 'cloud_agent'")
    op.execute("ALTER TYPE import_source_enum rename to import_source_tmp")
    op.execute("CREATE TYPE import_source_enum AS ENUM ( 'report', 'shell', 'agent' )")
    op.execute("ALTER TABLE command ALTER import_source TYPE import_source_enum"
               " USING import_source::TEXT::import_source_enum")
    op.execute("DROP TYPE import_source_tmp")
    op.drop_index(op.f('ix_cloud_agent_execution_workspace_id'), table_name='cloud_agent_execution')
    op.drop_index(op.f('ix_cloud_agent_execution_command_id'), table_name='cloud_agent_execution')
    op.drop_index(op.f('ix_cloud_agent_execution_cloud_agent_id'), table_name='cloud_agent_execution')
    op.drop_table('cloud_agent_execution')
    op.drop_table('cloud_agent')
