"""user_types_enum

Revision ID: 905261860ad0
Revises: b31fa447f00c
Create Date: 2022-05-13 15:19:34.717313+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '905261860ad0'
down_revision = 'b31fa447f00c'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE TYPE user_types AS ENUM ('ldap', 'local', 'saml')")
    op.add_column('faraday_user',
                  sa.Column('user_type', sa.Enum('ldap', 'local', 'saml', name='user_types'), nullable=True))
    op.execute("UPDATE faraday_user SET user_type = 'local'")
    op.execute("UPDATE faraday_user SET user_type = 'ldap' WHERE is_ldap = true")
    op.alter_column('faraday_user', 'user_type', nullable=False)
    op.drop_column('faraday_user', 'is_ldap')


def downgrade():
    op.add_column('faraday_user', sa.Column('is_ldap', sa.Boolean(), nullable=True))
    op.execute("UPDATE faraday_user SET is_ldap = CASE WHEN user_type = 'ldap' THEN true "
               "WHEN user_type = 'local' THEN false WHEN user_type = 'saml' THEN false END")
    op.alter_column('faraday_user', 'is_ldap', nullable=False)
    op.drop_column('faraday_user', 'user_type')
    op.execute("DROP TYPE user_types")
