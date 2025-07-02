"""delete bulk_create permission unit

Revision ID: 45a831782601
Revises: e2500923d887
Create Date: 2025-06-10 12:36:14.871788+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '45a831782601'
down_revision = 'e2500923d887'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'bulk_create';"
    )
    bulk_create_unit_id = result.scalar()

    if bulk_create_unit_id:
        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'create' AND permissions_unit_id = {bulk_create_unit_id};"  # nosec B608
        )
        action_id = result.scalar()

        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {action_id};"  # nosec B608
        )

        op.execute(
            "DELETE FROM permissions_unit_action WHERE permissions_unit_id = (SELECT id FROM permissions_unit WHERE name = 'bulk_create');"
        )

        op.execute(
            f"DELETE FROM permissions_unit WHERE id = {bulk_create_unit_id};"  # nosec B608
        )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'licenses';"
    )
    licenses_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'licenses';"
    )
    licenses_group_id = result.scalar()

    if licenses_unit_id and licenses_group_id:
        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'create' AND permissions_unit_id = {licenses_unit_id};"  # nosec B608
        )
        create_action_id = result.scalar()

        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'read' AND permissions_unit_id = {licenses_unit_id};"  # nosec B608
        )
        read_action_id = result.scalar()

        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'update' AND permissions_unit_id = {licenses_unit_id};"  # nosec B608
        )
        update_action_id = result.scalar()

        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = 'delete' AND permissions_unit_id = {licenses_unit_id};"  # nosec B608
        )
        delete_action_id = result.scalar()

        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {create_action_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {read_action_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {update_action_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {delete_action_id};"  # nosec B608
        )

        op.execute(
            "DELETE FROM permissions_unit_action WHERE permissions_unit_id = (SELECT id FROM permissions_unit WHERE name = 'licenses');"
        )

        op.execute(
            f"DELETE FROM permissions_unit WHERE id = {licenses_unit_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM permissions_group WHERE id = {licenses_group_id};"  # nosec B608
        )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'workspaces';"
    )
    workspaces_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'workspaces';"
    )
    workspaces_group_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'admin';"
    )
    admin_group_id = result.scalar()

    if workspaces_group_id:
        op.execute(
            f"UPDATE permissions_unit SET permissions_group_id = {admin_group_id} WHERE id = {workspaces_unit_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM permissions_group WHERE id = {workspaces_group_id};"  # nosec B608
        )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'settings';"
    )
    settings_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'settings';"
    )
    settings_group_id = result.scalar()

    if settings_group_id:
        op.execute(
            f"UPDATE permissions_unit SET permissions_group_id = {admin_group_id} WHERE id = {settings_unit_id};"  # nosec B608
        )

        op.execute(
            f"DELETE FROM permissions_group WHERE id = {settings_group_id};"  # nosec B608
        )


def downgrade():
    pass
