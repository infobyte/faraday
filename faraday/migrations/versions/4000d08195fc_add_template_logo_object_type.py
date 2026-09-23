"""add_template_logo_object_type

Revision ID: 4000d08195fc
Revises: ea8b5353bf9f
Create Date: 2026-06-30 19:21:12.848230+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4000d08195fc'
down_revision = 'ea8b5353bf9f'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE object_types ADD VALUE IF NOT EXISTS 'template_logo'")


def downgrade():
    op.execute("DELETE FROM file WHERE object_type = 'template_logo'")
