"""cloud agent active flag

Adds active to cloud_agent, to block a cloud agent (security scanner) from running.
Only used by the black edition; kept here too so the migration timeline stays a
single line across editions (both share this migrations directory).

Revision ID: 5833aa59133b
Revises: a53dbe714833
Create Date: 2026-10-01 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5833aa59133b'
down_revision = 'a53dbe714833'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('cloud_agent', sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('true')))


def downgrade():
    op.drop_column('cloud_agent', 'active')
