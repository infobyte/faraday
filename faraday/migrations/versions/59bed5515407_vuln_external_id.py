"""Vuln external id

Revision ID: 59bed5515407
Revises: 0305c9db7c32
Create Date: 2019-06-18 15:38:31.879725+00:00

"""

from alembic import op


# revision identifiers, used by Alembic.
revision = '59bed5515407'
down_revision = '2db31733fb78'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE vulnerability ADD COLUMN external_id TEXT')
    conn.execute('ALTER TABLE vulnerability_template ADD COLUMN external_id TEXT')


def downgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE vulnerability DROP COLUMN external_id')
    conn.execute('ALTER TABLE vulnerability_template DROP COLUMN external_id')
