"""user_types_enum

Revision ID: b1a7be9c0d98
Revises: 877dd088c8cb
Create Date: 2022-05-12 20:31:50.634691+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1a7be9c0d98'
down_revision = '877dd088c8cb'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('faraday_user', sa.Column('type', sa.Enum('ldap', 'local', 'saml', name='user_types'), nullable=False))


def downgrade():
    op.drop_column('faraday_user', 'type')
