"""access tokens roles

Revision ID: d350513b107e
Revises: 45a831782601
Create Date: 2025-07-08 17:35:08.550183+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'd350513b107e'
down_revision = '45a831782601'
branch_labels = None
depends_on = None


def upgrade():
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


def downgrade():
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
