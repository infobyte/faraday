"""add global scope token

Revision ID: 5fecdb3d57ae
Revises: 51b77832cfde
Create Date: 2026-01-30 13:48:04.286107+00:00

"""
from alembic import op
from faraday.server.models import UserToken

# revision identifiers, used by Alembic.
revision = '5fecdb3d57ae'
down_revision = '51b77832cfde'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE token_scopes ADD VALUE IF NOT EXISTS 'global'")


def downgrade():
    op.execute("DELETE FROM user_token WHERE scope = 'global'")

    scopes = [scope for scope in UserToken.SCOPES if scope != UserToken.GLOBAL_SCOPE]

    scopes_str = ', '.join(f"'{scope}'" for scope in scopes)

    op.execute(f"CREATE TYPE token_scopes_tmp AS ENUM({scopes_str})")

    op.execute("""
                    ALTER TABLE user_token
                    ALTER COLUMN scope
                    SET DATA TYPE token_scopes_tmp
                    USING scope::text::token_scopes_tmp
                """)

    op.execute("DROP TYPE token_scopes")

    op.execute("ALTER TYPE token_scopes_tmp RENAME TO token_scopes")
