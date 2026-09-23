"""fix asset owner permissions

Revision ID: b22cb062fae4
Revises: 5f70ccd6cfb9
Create Date: 2026-06-23 19:44:41.732691+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b22cb062fae4'
down_revision = '5f70ccd6cfb9'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()

    role_id = bind.execute(
        sa.text("SELECT id FROM faraday_role WHERE name = 'asset_owner'")
    ).scalar()

    whd_unit_id = bind.execute(
        sa.text("SELECT id FROM permissions_unit WHERE name = 'web_help_desk'")
    ).scalar()

    if whd_unit_id:
        unit_action_id = bind.execute(
            sa.text(
                "SELECT id FROM permissions_unit_action"
                " WHERE action_type = 'update' AND permissions_unit_id = :uid"
            ),
            {"uid": whd_unit_id},
        ).scalar()

        bind.execute(
            sa.text(
                "UPDATE role_permission SET allowed = false"
                " WHERE unit_action_id = :uaid AND role_id = :rid"
            ),
            {"uaid": unit_action_id, "rid": role_id},
        )

    ws_update_id = bind.execute(
        sa.text("""
            SELECT pua.id
            FROM permissions_unit_action pua
            JOIN permissions_unit pu ON pu.id = pua.permissions_unit_id
            WHERE pu.name = 'workspaces' AND pua.action_type = 'update'
        """)
    ).scalar()
    if ws_update_id:
        bind.execute(
            sa.text(
                "UPDATE role_permission SET allowed = false "
                "WHERE unit_action_id = :uid "
                "AND role_id != (SELECT id FROM faraday_role WHERE name = 'admin')"
            ),
            {"uid": ws_update_id},
        )


def downgrade():
    pass
