"""add import stats to command

Revision ID: 375b8764002c
Revises: 82a05afc9c2f
Create Date: 2026-08-11 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa
from faraday.server.fields import JSONType

# revision identifiers, used by Alembic.
revision = '375b8764002c'
down_revision = '82a05afc9c2f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('command', sa.Column('import_stats', JSONType(), nullable=True))


def downgrade():
    op.drop_column('command', 'import_stats')
