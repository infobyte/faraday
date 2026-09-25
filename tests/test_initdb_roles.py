"""Tests for the default roles seeded by initdb, focused on workspace_admin.

workspace_admin mirrors the pentester role over every permission unit (so it has
full access to workspace contents: vulnerabilities, hosts, services, comments,
credentials, agents, reports, ...), plus full CRUD on UNIT_WORKSPACES so it can
create/delete/edit/activate/lock/group workspaces. The generic per-assignee check
scopes all of that to the workspaces where the user is an allowed_user.
"""

import pytest
from sqlalchemy import text

from faraday.server.models import PermissionsUnitAction, User
from faraday.server.utils.permissions import (
    UNIT_COMMENTS,
    UNIT_HOSTS,
    UNIT_SERVICES,
    UNIT_SETTINGS,
    UNIT_USERS,
    UNIT_VULNERABILITIES,
    UNIT_WORKSPACES,
)
from faraday.utils.initdb import _exec_initdb

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION

CRUD = [CREATE, READ, UPDATE, DELETE]
# workspace contents workspace_admin must be able to fully manage (pentester-level)
CONTENT_UNITS = [UNIT_VULNERABILITIES, UNIT_HOSTS, UNIT_SERVICES, UNIT_COMMENTS]


def _allowed(session, role_name, unit_name, action):
    return session.execute(
        text(
            "SELECT rp.allowed FROM role_permission rp "
            "JOIN faraday_role r ON rp.role_id = r.id "
            "JOIN permissions_unit_action pua ON rp.unit_action_id = pua.id "
            "JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "
            "WHERE r.name = :role AND pu.name = :unit AND pua.action_type = :action"
        ),
        {'role': role_name, 'unit': unit_name, 'action': action},
    ).scalar()


def test_workspace_admin_role_constant():
    assert User.WORKSPACE_ADMIN_ROLE == 'workspace_admin'
    assert User.WORKSPACE_ADMIN_ROLE in User.ROLES


class TestInitdbWorkspaceAdmin:

    @pytest.fixture(autouse=True)
    def seeded(self, session):
        session.execute(text('DELETE FROM role_permission'))
        session.execute(text('DELETE FROM notification_allowed_roles'))
        session.execute(text('DELETE FROM roles_users'))
        session.execute(text('DELETE FROM faraday_role'))
        _exec_initdb(lambda stmt: session.execute(text(stmt)))

    def test_seeded_as_default_role(self, session):
        row = session.execute(
            text("SELECT weight, custom, description FROM faraday_role WHERE name = :role"),
            {'role': User.WORKSPACE_ADMIN_ROLE},
        ).one()
        assert row.custom is False
        assert row.weight == 15
        assert row.description

    def test_all_default_roles_seeded(self, session):
        names = session.execute(
            text("SELECT name FROM faraday_role WHERE custom = false")
        ).scalars().all()
        assert set(names) == set(User.ROLES)

    def test_can_create_and_delete_workspaces(self, session):
        # workspaces is elevated above pentester (which lacks create/update/delete)
        for action in CRUD:
            assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_WORKSPACES, action) is True

    def test_has_workspace_content_access(self, session):
        # The regression this guards: workspace_admin previously had NO rows for these
        # units and was denied (403) on vulns/hosts/services inside its own workspaces.
        for unit in CONTENT_UNITS:
            for action in CRUD:
                assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, unit, action) is True, (unit, action)

    def test_cannot_manage_users(self, session):
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, READ) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, UPDATE) is True
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, CREATE) is False
        assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_USERS, DELETE) is False

    def test_no_settings_access(self, session):
        for action in CRUD:
            assert _allowed(session, User.WORKSPACE_ADMIN_ROLE, UNIT_SETTINGS, action) is False

    def test_mirrors_pentester_except_workspaces(self, session):
        rows = session.execute(text(
            "SELECT pu.name AS unit, pua.action_type AS action, "
            "wsa.allowed AS wsa_allowed, pent.allowed AS pent_allowed "
            "FROM permissions_unit_action pua "
            "JOIN permissions_unit pu ON pua.permissions_unit_id = pu.id "
            "LEFT JOIN role_permission wsa ON wsa.unit_action_id = pua.id "
            "  AND wsa.role_id = (SELECT id FROM faraday_role WHERE name = 'workspace_admin') "
            "LEFT JOIN role_permission pent ON pent.unit_action_id = pua.id "
            "  AND pent.role_id = (SELECT id FROM faraday_role WHERE name = 'pentester')"
        )).fetchall()
        assert rows
        for r in rows:
            # workspace_admin has a row for every unit_action (complete profile)
            assert r.wsa_allowed is not None, ('missing row', r.unit, r.action)
            if r.unit == UNIT_WORKSPACES:
                assert r.wsa_allowed is True, (r.unit, r.action)
            else:
                expected = r.pent_allowed if r.pent_allowed is not None else False
                assert r.wsa_allowed == expected, (r.unit, r.action, r.wsa_allowed, expected)
