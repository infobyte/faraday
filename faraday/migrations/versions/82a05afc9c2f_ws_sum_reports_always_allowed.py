"""ws_sum_reports always allowed

Revision ID: 82a05afc9c2f
Revises: a1f2c9d4e6b7
Create Date: 2026-08-19 00:00:00.000000+00:00

"""
from alembic import op
from sqlalchemy import text

from faraday.server.utils.permissions import GROUP_ALL, GROUP_WS_SUM_REPORTS, UNIT_WS_SUM_REPORTS

# revision identifiers, used by Alembic.
revision = '82a05afc9c2f'
down_revision = 'a1f2c9d4e6b7'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        text(f"SELECT id FROM permissions_group WHERE name = '{GROUP_ALL}';")  # nosec B608
    )
    all_group_id = result.scalar()

    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = {all_group_id} "  # nosec B608
        f"WHERE name = '{UNIT_WS_SUM_REPORTS}';"
    )

    # INSERT .. ON CONFLICT covers both roles that already had a role_permission row
    # (forcing allowed=true, even if it was explicitly set to false) and roles that
    # never had a row for this unit at all (e.g. a custom role saved without this
    # group in its payload) -- a missing row is otherwise treated as allowed=false
    # by enforcement, so it would stay implicitly denied without this insert.
    op.execute(
        "INSERT INTO role_permission (unit_action_id, role_id, allowed) "
        "SELECT pua.id, r.id, true "
        "FROM permissions_unit_action pua "
        "CROSS JOIN faraday_role r "
        f"WHERE pua.permissions_unit_id = (SELECT id FROM permissions_unit WHERE name = '{UNIT_WS_SUM_REPORTS}') "  # nosec B608
        "ON CONFLICT (unit_action_id, role_id) DO UPDATE SET allowed = true;"
    )

    op.execute(
        f"DELETE FROM permissions_group WHERE name = '{GROUP_WS_SUM_REPORTS}';"  # nosec B608
    )


def downgrade():
    op.execute(f"INSERT INTO permissions_group (name) VALUES ('{GROUP_WS_SUM_REPORTS}');")  # nosec B608

    result = op.get_bind().execute(
        text(f"SELECT id FROM permissions_group WHERE name = '{GROUP_WS_SUM_REPORTS}';")  # nosec B608
    )
    group_id = result.scalar()

    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = {group_id} "  # nosec B608
        f"WHERE name = '{UNIT_WS_SUM_REPORTS}';"
    )
