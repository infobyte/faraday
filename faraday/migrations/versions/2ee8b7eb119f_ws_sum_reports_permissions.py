"""ws_sum_reports permissions

Revision ID: 2ee8b7eb119f
Revises: 2063ac75ffb1
Create Date: 2025-05-30 16:22:47.068338+00:00

"""
from alembic import op

from faraday.server.models import PermissionsUnitAction, Role
from faraday.server.utils.permissions import GROUP_WS_SUM_REPORTS, UNIT_WS_SUM_REPORTS

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION
ACTIONS = [CREATE, READ, UPDATE, DELETE]


# revision identifiers, used by Alembic.
revision = '2ee8b7eb119f'
down_revision = '2063ac75ffb1'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "SELECT setval('permissions_group_id_seq', (SELECT MAX(id) FROM permissions_group));"
    )

    op.execute(
        "SELECT setval('permissions_unit_id_seq', (SELECT MAX(id) FROM permissions_unit));"
    )

    op.execute(
        "SELECT setval('permissions_unit_action_id_seq', (SELECT MAX(id) FROM permissions_unit_action));"
    )

    op.execute(f"INSERT INTO permissions_group (name) VALUES ('{GROUP_WS_SUM_REPORTS}');")  # nosec B608

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_group WHERE name = '{GROUP_WS_SUM_REPORTS}';"  # nosec B608
    )
    group_id = result.scalar()

    op.execute(
        f"INSERT INTO permissions_unit (name, permissions_group_id) VALUES ('{UNIT_WS_SUM_REPORTS}', {group_id});"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit WHERE name = '{UNIT_WS_SUM_REPORTS}';"  # nosec B608
    )
    unit_id = result.scalar()

    op.execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES "
        f"('{CREATE}', {unit_id}), ('{READ}', {unit_id}), ('{UPDATE}', {unit_id}), ('{DELETE}', {unit_id});"  # nosec B608
    )

    permisison_unit_action_ids = []
    for action in ACTIONS:
        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = '{action}' AND permissions_unit_id = {unit_id};"  # nosec B608
        )
        permisison_unit_action_ids.append(result.scalar())

    roles = Role.query.all()
    for action_id in permisison_unit_action_ids:
        for role in roles:
            op.execute(
                f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({action_id}, {role.id}, true);"  # nosec B608
            )


def downgrade():
    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit WHERE name = '{UNIT_WS_SUM_REPORTS}';"  # nosec B608
    )
    unit_id = result.scalar()

    permisison_unit_action_ids = []
    for action in ACTIONS:
        result = op.get_bind().execute(
            f"SELECT id FROM permissions_unit_action WHERE action_type = '{action}' AND permissions_unit_id = {unit_id};"  # nosec B608
        )
        permisison_unit_action_ids.append(result.scalar())

    for action_id in permisison_unit_action_ids:
        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {action_id};"  # nosec B608
        )

    op.execute(
        f"DELETE FROM permissions_unit_action WHERE permissions_unit_id = (SELECT id FROM permissions_unit WHERE name = '{UNIT_WS_SUM_REPORTS}');"  # nosec B608
    )

    op.execute(
        f"DELETE FROM permissions_unit WHERE id = {unit_id};"  # nosec B608
    )

    op.execute(
        f"DELETE FROM permissions_group WHERE name = '{GROUP_WS_SUM_REPORTS}';"  # nosec B608
    )
