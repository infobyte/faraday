"""check important host

Revision ID: e03a13c41a67
Revises: 20f3d0c2f71f
Create Date: 2020-10-06 02:03:17.966397+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e03a13c41a67'
down_revision = '20f3d0c2f71f'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('host', sa.Column('important', sa.Boolean(), nullable=False, server_default='False'))


def downgrade():
    op.drop_column('host', 'important')
