"""clear preferences

Revision ID: 4423dd3f90be
Revises: e9a3ba96ea46
Create Date: 2024-10-17 14:18:03.830337+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '4423dd3f90be'
down_revision = 'e9a3ba96ea46'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("UPDATE faraday_user SET preferences = '{}';")


def downgrade():
    pass
