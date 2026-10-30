"""add features to agent

Revision ID: d3a85f1c7e92
Revises: c7e41d9a2b58
Create Date: 2026-10-30 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType


# revision identifiers, used by Alembic.
revision = 'd3a85f1c7e92'
down_revision = 'c7e41d9a2b58'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('agent', sa.Column('features', JSONType(), nullable=False, server_default=sa.text("'[]'")))


def downgrade():
    op.drop_column('agent', 'features')
