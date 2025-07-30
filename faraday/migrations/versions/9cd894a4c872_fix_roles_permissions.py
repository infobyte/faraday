"""fix roles permissions

Revision ID: 9cd894a4c872
Revises: e0c9670228b9
Create Date: 2025-07-30 19:52:40.768225+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '9cd894a4c872'
down_revision = 'e0c9670228b9'
branch_labels = None
depends_on = None


def upgrade():
    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE name = 'admin';"
    )
    admin_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE name = 'asset_owner';"
    )
    asset_owner_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE name = 'pentester';"
    )
    pentester_id = result.scalar()

    result = op.get_bind().execute(
        "SELECT id FROM faraday_role WHERE name = 'client';"
    )
    client_id = result.scalar()

    op.execute(
        "INSERT INTO faraday_role (id, name, weight, custom) VALUES (1001, 'admin_temp', 1000, true), "
        "(1002, 'asset_owner_temp', 1000, true), (1003, 'pentester_temp', 1000, true), (1004, 'client_temp', 1000, true);"
    )

    op.execute(
        "UPDATE role_permission SET role_id = 1001 WHERE role_id = 1;"
        "UPDATE role_permission SET role_id = 1002 WHERE role_id = 2;"
        "UPDATE role_permission SET role_id = 1003 WHERE role_id = 3;"
        "UPDATE role_permission SET role_id = 1004 WHERE role_id = 4;"
    )

    op.execute(
        f"UPDATE role_permission SET role_id = {admin_id} WHERE role_id = 1001;"  # nosec B608
        f"UPDATE role_permission SET role_id = {asset_owner_id} WHERE role_id = 1002;"  # nosec B608
        f"UPDATE role_permission SET role_id = {pentester_id} WHERE role_id = 1003;"  # nosec B608
        f"UPDATE role_permission SET role_id = {client_id} WHERE role_id = 1004;"  # nosec B608
    )

    op.execute(
        "DELETE FROM faraday_role WHERE weight = 1000;"
    )


def downgrade():
    pass
