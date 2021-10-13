"""add markdown column to exectuive reports

Revision ID: 5272b3f5a820
Revises: 2ca03a8feef5
Create Date: 2019-03-27 19:26:28.354078+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '5272b3f5a820'
down_revision = '2ca03a8feef5'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executive_report', sa.Column('markdown', sa.Boolean(), nullable=False, server_default='False'))


def downgrade():
    op.drop_column('executive_report', 'markdown')
