"""add (user_id, id) index on user_notification

Revision ID: a0b302b596ac
Revises: 5833aa59133b
Create Date: 2026-10-14 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'a0b302b596ac'
down_revision = '5833aa59133b'
branch_labels = None
depends_on = None

INDEX_NAME = 'ix_user_notification_user_id_id'


def upgrade():
    # Building this index can take a long time on large databases, so it is not created here.
    # Run `faraday-manage optimize-indices` to create it.
    pass


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
