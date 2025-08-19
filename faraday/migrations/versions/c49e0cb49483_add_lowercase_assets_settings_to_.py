"""add lowercase assets settings to workspace

Revision ID: c49e0cb49483
Revises: 000918b77c25
Create Date: 2025-06-09 19:19:46.281730+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c49e0cb49483'
down_revision = '000918b77c25'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('workspace', sa.Column('force_lowercase_assets', sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade():
    op.drop_column('workspace', 'force_lowercase_assets')
