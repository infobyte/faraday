"""add stages to cloud_agent_execution

The stages of a cloud agent run as the Cloud Agent Manager reports them
(black edition's cloud_agent_executions/<id>/progress). Added here too so
the migration timeline stays a single line across editions (both share this
migrations directory).

Revision ID: bb0860337f41
Revises: 6ed6d0c4a21c
Create Date: 2026-10-01 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = 'bb0860337f41'
down_revision = '6ed6d0c4a21c'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cloud_agent_execution', sa.Column('stages', JSONType(), nullable=True))
    op.add_column('cloud_agent_execution',
                  sa.Column('stages_version', sa.Integer(), nullable=False, server_default='0'))


def downgrade():
    op.drop_column('cloud_agent_execution', 'stages_version')
    op.drop_column('cloud_agent_execution', 'stages')
