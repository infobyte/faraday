"""improve executive reports

Revision ID: 76b8ca65b9e8
Revises: c49e0cb49483
Create Date: 2025-10-16 19:52:11.652666+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '76b8ca65b9e8'
down_revision = 'c49e0cb49483'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executive_report', sa.Column('is_preview', sa.Boolean(), nullable=False, server_default='false'))


def downgrade():
    op.drop_column('executive_report', 'is_preview')
