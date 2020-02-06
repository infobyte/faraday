"""create user preferences column

Revision ID: a39a3a6e3f99
Revises: 904a517a2f0c
Create Date: 2020-02-04 15:28:09.796949+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'a39a3a6e3f99'
down_revision = '904a517a2f0c'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute("ALTER TABLE faraday_user ADD COLUMN preferences jsonb not null default '{}'::jsonb")


def downgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE faraday_user DROP COLUMN "preferences"')
