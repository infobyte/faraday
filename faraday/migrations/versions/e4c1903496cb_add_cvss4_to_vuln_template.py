"""add cvss4 to vuln template

Revision ID: e4c1903496cb
Revises: d350513b107e
Create Date: 2025-07-22 16:14:36.192120+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e4c1903496cb'
down_revision = 'e0c9670228b9'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vulnerability_template', sa.Column('_cvss4_vector_string', sa.Text(), nullable=True))


def downgrade():
    op.drop_column('vulnerability_template', '_cvss4_vector_string')
