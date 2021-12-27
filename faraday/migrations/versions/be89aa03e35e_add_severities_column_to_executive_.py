"""Add severities column to executive reports

Revision ID: be89aa03e35e
Revises: 0d216660da28
Create Date: 2019-05-14 18:12:52.724079+00:00

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = 'be89aa03e35e'
down_revision = '59bed5515407'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE executive_report ADD COLUMN filter JSONB')


def downgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE executive_report DROP COLUMN filter')
