"""add jira scope

Revision ID: 000918b77c25
Revises: 2063ac75ffb1
Create Date: 2025-03-27 13:08:56.838630+00:00

"""
from alembic import op
from faraday.server.models import UserToken

# revision identifiers, used by Alembic.
revision = '000918b77c25'
down_revision = '2063ac75ffb1'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE token_scopes ADD VALUE IF NOT EXISTS 'jira'")


def downgrade():
    op.execute("DELETE FROM user_token WHERE scope = 'jira'")

    scopes = [scope for scope in UserToken.SCOPES if scope != UserToken.JIRA_SCOPE]

    scopes_str = ', '.join(f"'{scope}'" for scope in scopes)

    op.execute(f"CREATE TYPE token_scopes_tmp AS ENUM({scopes_str})")

    # Step 2: Alter the table to use the new enum type
    op.execute("""
                    ALTER TABLE user_token
                    ALTER COLUMN scope
                    SET DATA TYPE token_scopes_tmp
                    USING scope::text::token_scopes_tmp
                """)

    op.execute("DROP TYPE token_scopes")

    op.execute("ALTER TYPE token_scopes_tmp RENAME TO token_scopes")
