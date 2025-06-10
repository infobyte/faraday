"""delete bulk_create permission unit

Revision ID: 45a831782601
Revises: a29d52685b58
Create Date: 2025-06-10 12:36:14.871788+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '45a831782601'
down_revision = 'a29d52685b58'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'bulk_create';"
    )
    unit_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'create' AND permissions_unit_id = {unit_id};"  # nosec B608
    )
    action_id = result.scalar()

    op.execute(
        f"DELETE FROM role_permission WHERE unit_action_id = {action_id};"  # nosec B608
    )

    op.execute(
        "DELETE FROM permissions_unit_action WHERE permissions_unit_id = (SELECT id FROM permissions_unit WHERE name = 'bulk_create');"
    )

    op.execute(
        f"DELETE FROM permissions_unit WHERE id = {unit_id};"  # nosec B608
    )


def downgrade():
    pass
