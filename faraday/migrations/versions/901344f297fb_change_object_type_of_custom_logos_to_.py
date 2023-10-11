"""change object_type of custom logos to report_logo

Revision ID: 901344f297fb
Revises: 73854f804a8d
Create Date: 2023-07-13 17:38:32.651676+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '901344f297fb'
down_revision = '73854f804a8d'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE object_types ADD VALUE IF NOT EXISTS 'report_logo'")
    op.execute("UPDATE file SET object_type = 'report_logo' WHERE object_type = 'executive_report' AND name = 'custom_logo'")


def downgrade():
    op.execute("UPDATE file SET object_type = 'executive_report' WHERE object_type = 'report_logo' AND name = 'custom_logo'")
