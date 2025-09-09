"""agents category

Revision ID: 75c38da2da8a
Revises: 39ddd3ca3a20
Create Date: 2025-01-27 20:36:41.962127+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType


revision = '75c38da2da8a'
down_revision = '39ddd3ca3a20'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cloud_agent', sa.Column('category', JSONType(), nullable=True))
    op.add_column('executor', sa.Column('category', JSONType(), nullable=True))
    op.add_column('executor', sa.Column('tool', sa.String(length=50), nullable=True))
    op.add_column('agent_execution', sa.Column('triggered_by', sa.String(), nullable=True))
    op.add_column('cloud_agent_execution', sa.Column('triggered_by', sa.String(), nullable=True))
    op.add_column('agent_execution', sa.Column('run_uuid', sa.dialects.postgresql.UUID(), nullable=True))
    op.add_column('cloud_agent_execution', sa.Column('run_uuid', sa.dialects.postgresql.UUID(), nullable=True))
    op.add_column('executor', sa.Column('parameters_data', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('cloud_agent', sa.Column('parameters_data', sa.JSON(), nullable=False, server_default='{}'))
    op.add_column('agent', sa.Column('description', sa.Text(), nullable=False, server_default=''))
    op.add_column('cloud_agent', sa.Column('description', sa.Text(), nullable=False, server_default=''))
    op.add_column('cloud_agent', sa.Column('tools_count', sa.Integer, nullable=False, server_default='1'))
    op.add_column('cloud_agent_execution', sa.Column('tasks_completed', sa.Integer, nullable=False, server_default='0'))

    # Adding indexes on run_uuid for better GROUP BY performance
    op.execute("CREATE INDEX IF NOT EXISTS ix_agent_execution_run_uuid ON agent_execution (run_uuid)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_cloud_agent_execution_run_uuid ON cloud_agent_execution (run_uuid)")


def downgrade():
    op.execute("DROP INDEX IF EXISTS ix_agent_execution_run_uuid")
    op.execute("DROP INDEX IF EXISTS ix_cloud_agent_execution_run_uuid")

    op.drop_column('executor', 'tool')
    op.drop_column('executor', 'category')
    op.drop_column('cloud_agent', 'category')
    op.drop_column('cloud_agent_execution', 'triggered_by')
    op.drop_column('agent_execution', 'triggered_by')
    op.drop_column('agent_execution', 'run_uuid')
    op.drop_column('cloud_agent_execution', 'run_uuid')
    op.drop_column('executor', 'parameters_data')
    op.drop_column('cloud_agent', 'parameters_data')
    op.drop_column('agent', 'description')
    op.drop_column('cloud_agent', 'description')
    op.drop_column('cloud_agent', 'tools_count')
    op.drop_column('cloud_agent_execution', 'tasks_completed')
