"""add system import_source

Adds 'system' to the command.import_source enum, for Command rows created by
internal background tasks (not a real scan/report import). This value is only
consumed by the black edition (risk score profile reassignment tracking) -
kept here too, unused, so the migration timeline stays a single line across
editions instead of forking (both share this migrations directory).

Revision ID: 6ed6d0c4a21c
Revises: a59b5b9dd0fb
Create Date: 2026-09-14 00:00:00.000000+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '6ed6d0c4a21c'
down_revision = 'a59b5b9dd0fb'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE import_source_enum ADD VALUE IF NOT EXISTS 'system'")


def downgrade():
    op.execute("DELETE FROM command WHERE import_source = 'system'")
