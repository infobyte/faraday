"""sync object_types enum

Revision ID: d8bcf5cf64ee
Revises: b3e7f1a2c904
Create Date: 2026-06-16 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'd8bcf5cf64ee'
down_revision = 'b3e7f1a2c904'
branch_labels = None
depends_on = None


# Snapshot of OBJECT_TYPES at this revision. Hardcoded on purpose: a migration is a
# point-in-time artifact, so future additions get their own ADD VALUE migration.
OBJECT_TYPE_VALUES = (
    'vulnerability', 'host', 'credential', 'service', 'source_code', 'comment',
    'executive_report', 'workspace', 'project_task', 'user', 'executivereport',
    'agent', 'agentexecution', 'command', 'report_logo', 'task', 'report_template',
)


def upgrade():
    with op.get_context().autocommit_block():
        for value in OBJECT_TYPE_VALUES:
            op.execute(f"ALTER TYPE object_types ADD VALUE IF NOT EXISTS '{value}'")


def downgrade():
    # Postgres cannot remove values from an enum.
    pass
