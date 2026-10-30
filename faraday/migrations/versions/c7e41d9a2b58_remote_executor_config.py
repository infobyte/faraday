"""add remote executor config columns to executor and agent

Revision ID: c7e41d9a2b58
Revises: a0b302b596ac
Create Date: 2026-10-30 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType


# revision identifiers, used by Alembic.
revision = 'c7e41d9a2b58'
down_revision = 'a0b302b596ac'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executor', sa.Column('enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('executor', sa.Column('varenvs_set', JSONType(), nullable=False, server_default=sa.text("'[]'")))
    op.add_column('agent', sa.Column('features', JSONType(), nullable=False, server_default=sa.text("'[]'")))
    op.add_column('agent', sa.Column('capabilities', JSONType(), nullable=False, server_default=sa.text("'[]'")))
    op.add_column('agent', sa.Column('manifests_digest', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('agent', 'manifests_digest')
    op.drop_column('agent', 'capabilities')
    op.drop_column('agent', 'features')
    op.drop_column('executor', 'varenvs_set')
    op.drop_column('executor', 'enabled')
