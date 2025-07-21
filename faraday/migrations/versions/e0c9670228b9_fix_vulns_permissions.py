"""fix vulns permissions

Revision ID: e0c9670228b9
Revises: d350513b107e
Create Date: 2025-07-21 16:03:43.794428+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'e0c9670228b9'
down_revision = 'd350513b107e'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'vulnerabilities';"
    )
    vulns_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'create' AND permissions_unit_id = {vulns_unit_id};"  # nosec B608
    )

    create_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {create_action_id} AND (role_id = 1 OR role_id = 3);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'delete' AND permissions_unit_id = {vulns_unit_id};"  # nosec B608
    )

    delete_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {delete_action_id} AND (role_id = 1 OR role_id = 3);"  # nosec B608
    )


def downgrade():
    pass
