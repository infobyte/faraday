"""add service desk scope

Revision ID: 7c223e63007f
Revises: 391de8e3c453
Create Date: 2024-08-14 15:18:41.873355+00:00

"""
from alembic import op
from faraday.server.models import UserToken

# revision identifiers, used by Alembic.
revision = '7c223e63007f'
down_revision = '391de8e3c453'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE token_scopes ADD VALUE IF NOT EXISTS 'service_desk'")


def downgrade():
    op.execute("DELETE FROM user_token WHERE scope = 'service_desk'")

    scopes = [scope for scope in UserToken.SCOPES if scope != UserToken.SERVICE_DESK_SCOPE]

    scopes_str = ', '.join(f"'{scope}'" for scope in scopes)

    op.execute(f"CREATE TYPE token_scopes_tmp AS ENUM({scopes_str})")

    # Step 2: Alter the table to use the new enum type
    op.execute("""
                ALTER TABLE user_token
                ALTER COLUMN scope
                SET DATA TYPE token_scopes_tmp
                USING scope::text::token_scopes_tmp
            """)

    # Step 3: Drop the old enum type
    op.execute("DROP TYPE token_scopes")

    # Step 4: Rename the new enum type to the original one
    op.execute("ALTER TYPE token_scopes_tmp RENAME TO token_scopes")
    # ### end Alembic commands ###
