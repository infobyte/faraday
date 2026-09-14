"""add_website_to_executor_and_cloud_agent

Revision ID: 1c0d3377b5cc
Revises: b22cb062fae4
Create Date: 2026-06-11 13:08:53.685908+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1c0d3377b5cc'
down_revision = 'b22cb062fae4'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executor', sa.Column('website', sa.Text(), nullable=True))
    op.add_column('cloud_agent', sa.Column('website', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('executor', 'website')
    op.drop_column('cloud_agent', 'website')
