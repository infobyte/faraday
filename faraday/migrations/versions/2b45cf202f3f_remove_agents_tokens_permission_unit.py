"""remove agents_tokens permission unit

The GET /agent_token endpoint no longer has its own permission unit; it now
reuses UNIT_AGENTS (CREATE action), the same unit AgentView already checks
when an agent registers itself. This drops the now-unused 'agents_tokens'
permissions_unit and its associated permissions_unit_action/role_permission
rows.

Revision ID: 2b45cf202f3f
Revises: c81b3d92f4a7
Create Date: 2026-08-07 00:00:00.000000+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '2b45cf202f3f'
down_revision = 'c81b3d92f4a7'
branch_labels = None
depends_on = None

# Hardcoded instead of imported from faraday.server.utils.permissions: this
# migration documents the removal of that unit/group, so it must keep working
# even after the constants themselves are deleted from the live module.
GROUP_AGENTS = 'agents'
UNIT_AGENTS_TOKENS = 'agents_tokens'
READ = 'read'

_UNIT_ACTION_SUBQUERY = (
    f"(SELECT pua.id FROM permissions_unit_action pua "  # nosec B608
    f"JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "  # nosec B608
    f"WHERE pu.name = '{UNIT_AGENTS_TOKENS}')"
)


def upgrade():
    op.execute(
        f"DELETE FROM role_permission WHERE unit_action_id = {_UNIT_ACTION_SUBQUERY}"  # nosec B608
    )
    op.execute(
        f"DELETE FROM permissions_unit_action WHERE permissions_unit_id = "  # nosec B608
        f"(SELECT id FROM permissions_unit WHERE name = '{UNIT_AGENTS_TOKENS}')"
    )
    op.execute(
        f"DELETE FROM permissions_unit WHERE name = '{UNIT_AGENTS_TOKENS}'"  # nosec B608
    )


def downgrade():
    op.execute(
        f"INSERT INTO permissions_unit (name, permissions_group_id) "  # nosec B608
        f"VALUES ('{UNIT_AGENTS_TOKENS}', (SELECT id FROM permissions_group WHERE name = '{GROUP_AGENTS}'))"
    )
    op.execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) "  # nosec B608
        f"VALUES ('{READ}', (SELECT id FROM permissions_unit WHERE name = '{UNIT_AGENTS_TOKENS}'))"
    )
    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) "  # nosec B608
        f"SELECT {_UNIT_ACTION_SUBQUERY}, r.id, (r.name = 'admin') "  # nosec B608
        f"FROM faraday_role r "  # nosec B608
        f"WHERE r.name IN ('admin', 'asset_owner', 'pentester', 'client', 'workspace_admin')"
    )
