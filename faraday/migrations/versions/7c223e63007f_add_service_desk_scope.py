"""add service desk scope

Revision ID: 7c223e63007f
Revises: ad29e4bcf2cf
Create Date: 2024-08-14 15:18:41.873355+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '7c223e63007f'
down_revision = 'ad29e4bcf2cf'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE token_scopes ADD VALUE IF NOT EXISTS 'service_desk'")


def downgrade():
    op.execute("DELETE FROM user_token WHERE token_scopes = 'service_desk'")
