"""add partial index on user_notification for unread count

Revision ID: 5f70ccd6cfb9
Revises: b3e7f1a2c904
Create Date: 2026-04-15 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '5f70ccd6cfb9'
down_revision = 'b3e7f1a2c904'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_notification_user_id_unread "
            "ON user_notification (user_id) WHERE read = false"
        )


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS ix_user_notification_user_id_unread"
        )
