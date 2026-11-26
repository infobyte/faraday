"""fix vulnerability_status_history.status enum type

eb9b98d0b4d0 typed vulnerability_status_history.status with the vulnerability_statuses
enum, while the model names it vulnerability_status_history_statuses. Single-row
inserts never cast, so it went unnoticed; since the triage fields, one update can write
several history rows and SQLAlchemy casts each parameter to the model's type name, which
does not exist on migrated databases. Databases created with initdb already use the
model's type and are left untouched.

Revision ID: 2820045ab99e
Revises: 2a3b4c5d6e7f
Create Date: 2026-11-26 00:00:00.000000+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2820045ab99e'
down_revision = '2a3b4c5d6e7f'
branch_labels = None
depends_on = None

TYPE_NAME = 'vulnerability_status_history_statuses'
STATUSES = ('open', 'closed', 're-opened', 'risk-accepted')


def upgrade():
    conn = op.get_bind()
    current_type = conn.execute(sa.text(
        "SELECT udt_name FROM information_schema.columns "
        "WHERE table_schema = current_schema() "
        "AND table_name = 'vulnerability_status_history' AND column_name = 'status'"
    )).scalar()
    if current_type == TYPE_NAME:
        return

    labels = ', '.join(f"'{status}'" for status in STATUSES)
    op.execute(
        "DO $$ BEGIN "
        f"CREATE TYPE {TYPE_NAME} AS ENUM ({labels}); "
        "EXCEPTION WHEN duplicate_object THEN NULL; "
        "END $$"
    )
    op.execute(
        "ALTER TABLE vulnerability_status_history "
        f"ALTER COLUMN status TYPE {TYPE_NAME} USING status::text::{TYPE_NAME}"
    )


def downgrade():
    # Going back to vulnerability_statuses would bring the failing inserts back, and
    # databases created with initdb never had it, so the column keeps the model's type.
    pass
