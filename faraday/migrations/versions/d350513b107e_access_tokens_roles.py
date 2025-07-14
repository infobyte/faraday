"""access tokens roles

Revision ID: d350513b107e
Revises: 45a831782601
Create Date: 2025-07-08 17:35:08.550183+00:00

"""
from alembic import op

from faraday.server.models import PermissionsUnitAction

CREATE = PermissionsUnitAction.CREATE_ACTION
READ = PermissionsUnitAction.READ_ACTION
UPDATE = PermissionsUnitAction.UPDATE_ACTION
DELETE = PermissionsUnitAction.DELETE_ACTION
TAG = PermissionsUnitAction.TAG_ACTION


# revision identifiers, used by Alembic.
revision = 'd350513b107e'
down_revision = '45a831782601'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        "SELECT setval('permissions_unit_action_id_seq', (SELECT MAX(id) FROM permissions_unit_action));"
    )

    op.execute(
        "SELECT setval('permissions_unit_id_seq', (SELECT MAX(id) FROM permissions_unit));"
    )

    op.execute(
        "SELECT setval('permissions_group_id_seq', (SELECT MAX(id) FROM permissions_group));"
    )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'all';"
    )
    all_group_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'user_tokens';"
    )
    user_tokens_unit_id = result.scalar()

    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = {all_group_id} WHERE id = {user_tokens_unit_id};"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{CREATE}' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    create_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{READ}' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    read_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{UPDATE}' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    update_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{DELETE}' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    delete_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {create_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {read_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {update_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {delete_action_id};"  # nosec B608
    )

    with op.get_context().autocommit_block():
        op.execute(f"ALTER TYPE action_types ADD VALUE IF NOT EXISTS '{TAG}'")  # nosec B608

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'vulnerabilities';"
    )
    vulns_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'hosts';"
    )
    hosts_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'services';"
    )
    services_unit_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'workspaces';"
    )
    workspaces_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES ('{TAG}', {vulns_unit_id}), ('{TAG}', {hosts_unit_id}), ('{TAG}', {services_unit_id}), ('{TAG}', {workspaces_unit_id}) RETURNING id;"  # nosec B608
    )

    inserted_ids = [row[0] for row in result.fetchall()]

    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE id > 4;"
    )

    roles_ids = [row[0] for row in result.fetchall()]

    for id in inserted_ids:
        op.execute(
            f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({id}, 1, true), ({id}, 2, true), ({id}, 3, true), ({id}, 4, false);"  # nosec B608
        )
        for role_id in roles_ids:
            op.execute(
                f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({id}, {role_id}, false);"  # nosec B608
            )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{workspaces_unit_id}' AND action_type = '{UPDATE}';"  # nosec B608
    )
    ws_update_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {ws_update_id} AND (role_id = 2 OR role_id = 3);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{services_unit_id}' AND action_type = '{CREATE}';"  # nosec B608
    )
    sv_create_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{services_unit_id}' AND action_type = '{UPDATE}';"  # nosec B608
    )
    sv_update_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{services_unit_id}' AND action_type = '{DELETE}';"  # nosec B608
    )
    sv_delete_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {sv_create_id} AND role_id = 2;"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {sv_update_id} AND role_id = 2;"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {sv_delete_id} AND role_id = 2;"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{hosts_unit_id}' AND action_type = '{CREATE}';"  # nosec B608
    )
    ht_create_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{hosts_unit_id}' AND action_type = '{UPDATE}';"  # nosec B608
    )
    ht_update_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE permissions_unit_id = '{hosts_unit_id}' AND action_type = '{DELETE}';"  # nosec B608
    )
    ht_delete_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {ht_create_id} AND role_id = 2;"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {ht_update_id} AND role_id = 2;"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {ht_delete_id} AND role_id = 2;"  # nosec B608
    )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'preferences';"
    )
    preferences_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{CREATE}' AND permissions_unit_id = {preferences_unit_id};"  # nosec B608
    )
    create_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = true WHERE unit_action_id = {create_action_id};"  # nosec B608
    )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'planners';"
    )
    planners_group_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'planners';"
    )
    planners_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{UPDATE}' AND permissions_unit_id = {planners_unit_id};"  # nosec B608
    )
    update_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {update_action_id} AND role_id != 1;"  # nosec B608
    )

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit (name, permissions_group_id) VALUES ('tasks', {planners_group_id}) RETURNING id;"  # nosec B608
    )

    tasks_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES ('{CREATE}', {tasks_unit_id}) RETURNING id;"  # nosec B608
    )

    create_action_id = result.scalar()

    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({create_action_id}, 1, true), ({create_action_id}, 2, false), ({create_action_id}, 3, false), ({create_action_id}, 4, false);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES ('{READ}', {tasks_unit_id}) RETURNING id;"  # nosec B608
    )

    read_action_id = result.scalar()

    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({read_action_id}, 1, true), ({read_action_id}, 2, true), ({read_action_id}, 3, true), ({read_action_id}, 4, true);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES ('{UPDATE}', {tasks_unit_id}) RETURNING id;"  # nosec B608
    )

    update_action_id = result.scalar()

    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({update_action_id}, 1, true), ({update_action_id}, 2, true), ({update_action_id}, 3, true), ({update_action_id}, 4, true);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"INSERT INTO permissions_unit_action (action_type, permissions_unit_id) VALUES ('{DELETE}', {tasks_unit_id}) RETURNING id;"  # nosec B608
    )

    delete_action_id = result.scalar()

    op.execute(
        f"INSERT INTO role_permission (unit_action_id, role_id, allowed) VALUES ({delete_action_id}, 1, true), ({delete_action_id}, 2, false), ({delete_action_id}, 3, false), ({delete_action_id}, 4, false);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {CREATE} AND permissions_unit_id = {vulns_unit_id};"  # nosec B608
    )

    create_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {create_action_id};"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {DELETE} AND permissions_unit_id = {vulns_unit_id};"  # nosec B608
    )

    delete_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {delete_action_id};"  # nosec B608
    )

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'credentials';"
    )
    credentials_unit_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {CREATE} AND permissions_unit_id = {credentials_unit_id};"  # nosec B608
    )

    create_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {create_action_id} AND (role_id = 2 OR role_id = 4);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {READ} AND permissions_unit_id = {credentials_unit_id};"  # nosec B608
    )

    read_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {read_action_id} AND (role_id = 2 OR role_id = 4);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {UPDATE} AND permissions_unit_id = {credentials_unit_id};"  # nosec B608
    )

    update_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {update_action_id} AND (role_id = 2 OR role_id = 4);"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = {DELETE} AND permissions_unit_id = {credentials_unit_id};"  # nosec B608
    )

    delete_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {delete_action_id} AND (role_id = 2 OR role_id = 4);"  # nosec B608
    )


def downgrade():
    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = '{TAG}';"  # nosec B608
    )

    tag_actions_ids = [row[0] for row in result.fetchall()]

    for tag_action_id in tag_actions_ids:
        op.execute(
            f"DELETE FROM role_permission WHERE unit_action_id = {tag_action_id};"  # nosec B608
        )

    op.execute(
        f"DELETE FROM permissions_unit_action WHERE action_type = '{TAG}';"  # nosec B608
    )

    actions = [action for action in PermissionsUnitAction.ACTIONS if action != TAG]
    actions_str = ', '.join(f"'{action}'" for action in actions)
    op.execute(f"CREATE TYPE action_types_tmp AS ENUM({actions_str})")
    op.execute("ALTER TABLE permissions_unit_action ALTER COLUMN action_type SET DATA TYPE action_types_tmp USING action_type::text::action_types_tmp")
    op.execute("DROP TYPE action_types")
    op.execute("ALTER TYPE action_types_tmp RENAME TO action_types")

    result = op.get_bind().execute(
        "SELECT id FROM permissions_group WHERE name = 'admin';"
    )
    admin_group_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM permissions_unit WHERE name = 'user_tokens';"
    )
    user_tokens_unit_id = result.scalar()

    op.execute(
        f"UPDATE permissions_unit SET permissions_group_id = {admin_group_id} WHERE id = {user_tokens_unit_id};"  # nosec B608
    )

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'create' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    create_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'read' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    read_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'update' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    update_action_id = result.scalar()

    result = op.get_bind().execute(
        f"SELECT id FROM permissions_unit_action WHERE action_type = 'delete' AND permissions_unit_id = {user_tokens_unit_id};"  # nosec B608
    )
    delete_action_id = result.scalar()

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {create_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {read_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {update_action_id};"  # nosec B608
    )

    op.execute(
        f"UPDATE role_permission SET allowed = false WHERE unit_action_id = {delete_action_id};"  # nosec B608
    )
