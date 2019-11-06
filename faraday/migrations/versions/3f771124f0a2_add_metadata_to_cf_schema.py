"""add metadata to cf schema

Revision ID: 3f771124f0a2
Revises: 1dbe9e8e4247
Create Date: 2019-10-24 14:47:47.177057+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3f771124f0a2'
down_revision = '1dbe9e8e4247'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('custom_fields_schema', sa.Column('field_metadata', sa.JSON, nullable=True))


def downgrade():
    op.drop_column('custom_fields_schema', 'field_metadata')
