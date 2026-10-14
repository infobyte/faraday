"""add (user_id, id) index on user_notification

Revision ID: a0b302b596ac
Revises: 6ed6d0c4a21c
Create Date: 2026-10-14 00:00:00.000000+00:00

"""
import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = 'a0b302b596ac'
down_revision = '6ed6d0c4a21c'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        # A failed CONCURRENTLY build leaves an invalid index that IF NOT EXISTS would skip
        invalid = op.get_bind().execute(sa.text(
            "SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE c.relname = 'ix_user_notification_user_id_id' AND NOT i.indisvalid"
        )).scalar()
        if invalid:
            op.execute("DROP INDEX CONCURRENTLY IF EXISTS ix_user_notification_user_id_id")
        op.execute(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_user_notification_user_id_id "
            "ON user_notification (user_id, id)"
        )


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "DROP INDEX CONCURRENTLY IF EXISTS ix_user_notification_user_id_id"
        )
