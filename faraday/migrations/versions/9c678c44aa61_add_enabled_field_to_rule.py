"""add enabled field to rule

Revision ID: 9c678c44aa61
Revises: 282ac9b6569f
Create Date: 2020-04-08 18:11:04.761114+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9c678c44aa61'
down_revision = 'b1d15a55556d'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('rule', sa.Column('enabled', sa.Boolean, default=True, nullable=False, server_default='True'))


def downgrade():
    op.drop_column('rule', 'enabled')
