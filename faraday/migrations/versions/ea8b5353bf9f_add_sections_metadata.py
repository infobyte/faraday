"""add sections_metadata

Revision ID: ea8b5353bf9f
Revises: a94bf314d524
Create Date: 2026-04-15 16:46:42.520082+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType


# revision identifiers, used by Alembic.
revision = 'ea8b5353bf9f'
down_revision = 'a94bf314d524'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executive_report', sa.Column('sections_metadata', JSONType(), nullable=False, server_default='{}'))


def downgrade():
    op.drop_column('executive_report', 'sections_metadata')
