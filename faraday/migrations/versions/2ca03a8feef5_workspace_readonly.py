"""empty message

Revision ID: 2ca03a8feef5
Revises: 8a10ff3926a5
Create Date: 2019-01-15 13:02:21.000699+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2ca03a8feef5'
down_revision = '8a10ff3926a5'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('workspace', sa.Column('readonly', sa.Boolean(), nullable=False, server_default='False'))


def downgrade():
    op.drop_column('workspace', 'readonly')
