"""add (user_id, id) index on user_notification

Revision ID: a0b302b596ac
Revises: 6ed6d0c4a21c
Create Date: 2026-10-14 00:00:00.000000+00:00

"""
import time

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = 'a0b302b596ac'
down_revision = '6ed6d0c4a21c'
branch_labels = None
depends_on = None

INDEX_NAME = 'ix_user_notification_user_id_id'
CREATE_INDEX = f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {INDEX_NAME} ON user_notification (user_id, id)"


def _index_valid(bind):
    return bind.execute(sa.text(
        "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid WHERE c.relname = :name"
    ), {'name': INDEX_NAME}).scalar()


def upgrade():
    context = op.get_context()
    with context.autocommit_block():
        if context.as_sql:
            op.execute(CREATE_INDEX)
            return
        bind = op.get_bind()
        # Serialize concurrent runs (e.g. several pods migrating at once). Polling instead of a blocking
        # lock keeps no snapshot open while waiting, which the concurrent build would wait for
        lock = sa.text("SELECT pg_try_advisory_lock(hashtext(:name))")
        while not bind.execute(lock, {'name': INDEX_NAME}).scalar():
            time.sleep(1)
        try:
            # A failed CONCURRENTLY build leaves an invalid index that IF NOT EXISTS would skip
            if _index_valid(bind) is False:
                op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
            op.execute(CREATE_INDEX)
            if not _index_valid(bind):
                raise RuntimeError(f"{INDEX_NAME} is not valid after creation")
        finally:
            bind.execute(sa.text("SELECT pg_advisory_unlock(hashtext(:name))"), {'name': INDEX_NAME})


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {INDEX_NAME}")
