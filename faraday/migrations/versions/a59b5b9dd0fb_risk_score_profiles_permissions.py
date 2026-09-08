"""risk score profiles permissions

Seeds the risk_score_profiles permissions unit (Risk Score Profiles epic) with full
CRUD granted to both 'admin' and 'workspace_admin'. Row-level rules that the coarse
role/unit/action model can't express - a workspace_admin may only edit/delete profiles
they authored, and only while unused by any workspace, but may assign any profile
(their own or another author's) to a workspace they administer - are enforced in the
API view code, not here.

Revision ID: a59b5b9dd0fb
Revises: 73198eab4b2a
Create Date: 2026-09-08 18:29:27.554132+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a59b5b9dd0fb'
down_revision = '73198eab4b2a'
branch_labels = None
depends_on = None

# Hardcoded instead of imported from faraday.server.utils.permissions/models, following
# 2b45cf202f3f: this migration must keep working even if those constants change later.
#
# GROUP_ADMIN (not GROUP_WORKSPACES) is used here on purpose: the fresh-install bootstrap
# (faraday/utils/initdb.py, used both by new instances and the test suite) never creates a
# 'workspaces' permissions_group row - UNIT_WORKSPACES itself is filed under 'admin' there -
# so referencing 'workspaces' would insert a NULL permissions_group_id on those installs.
# permissions_group is a display/categorization dimension only (get_unit_action_permission
# never reads it), so this has no effect on authorization.
GROUP_ADMIN = 'admin'
UNIT_RISK_SCORE_PROFILES = 'risk_score_profiles'
CREATE = 'create'
READ = 'read'
UPDATE = 'update'
DELETE = 'delete'
ADMIN_ROLE = 'admin'
WORKSPACE_ADMIN_ROLE = 'workspace_admin'

_UNIT_SUBQUERY = f"(SELECT id FROM permissions_unit WHERE name = '{UNIT_RISK_SCORE_PROFILES}')"


def upgrade():
    op.execute(
        "INSERT INTO permissions_unit (name, permissions_group_id) "  # nosec B608
        f"VALUES ('{UNIT_RISK_SCORE_PROFILES}', "
        f"(SELECT id FROM permissions_group WHERE name = '{GROUP_ADMIN}'))"
    )
    op.execute(
        "INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES "  # nosec B608
        f"('{CREATE}', {_UNIT_SUBQUERY}), "
        f"('{READ}', {_UNIT_SUBQUERY}), "
        f"('{UPDATE}', {_UNIT_SUBQUERY}), "
        f"('{DELETE}', {_UNIT_SUBQUERY})"
    )
    op.execute(
        "INSERT INTO role_permission (unit_action_id, role_id, allowed) "  # nosec B608
        "SELECT pua.id, r.id, true "
        "FROM permissions_unit_action pua "
        f"JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id AND pu.name = '{UNIT_RISK_SCORE_PROFILES}' "
        "JOIN faraday_role r ON r.name IN "
        f"('{ADMIN_ROLE}', '{WORKSPACE_ADMIN_ROLE}')"
    )


def downgrade():
    op.execute(
        f"DELETE FROM role_permission WHERE unit_action_id IN "  # nosec B608
        "(SELECT id FROM permissions_unit_action WHERE permissions_unit_id = "
        f"{_UNIT_SUBQUERY})"
    )
    op.execute(
        f"DELETE FROM permissions_unit_action WHERE permissions_unit_id = {_UNIT_SUBQUERY}"  # nosec B608
    )
    op.execute(
        f"DELETE FROM permissions_unit WHERE name = '{UNIT_RISK_SCORE_PROFILES}'"  # nosec B608
    )
