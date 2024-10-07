"""user session_id

Revision ID: 907c72c8d391
Revises: ad29e4bcf2cf
Create Date: 2024-09-18 13:34:52.883133+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '907c72c8d391'
down_revision = 'ad29e4bcf2cf'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('faraday_user', sa.Column('session_id', sa.String(length=64), nullable=True))


def downgrade():
    op.drop_column('faraday_user', 'session_id')
