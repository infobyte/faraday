"""report_template object type

Revision ID: b5065f401599
Revises: 1e95dde5b9c8
Create Date: 2023-03-23 12:47:14.125405+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b5065f401599'
down_revision = '1e95dde5b9c8'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE object_types ADD VALUE IF NOT EXISTS 'report_template'")


def downgrade():
    op.execute("DELETE FROM file WHERE object_type = 'report_template'")
