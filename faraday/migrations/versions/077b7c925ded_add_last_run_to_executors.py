"""add last_run to executors

Revision ID: 077b7c925ded
Revises: 6471033046cb
Create Date: 2021-02-26 15:17:31.824177+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '077b7c925ded'
down_revision = 'a643e5316b5e'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executor', sa.Column('last_run', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column('executor', 'last_run')
