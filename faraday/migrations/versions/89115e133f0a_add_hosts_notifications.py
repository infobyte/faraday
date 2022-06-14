"""Add hosts notifications

Revision ID: 89115e133f0a
Revises: 5d7a930c439e
Create Date: 2021-07-26 17:18:43.521015+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
from faraday.server.models import NotificationSubscription, NotificationSubscriptionWebSocketConfig, User

revision = '89115e133f0a'
down_revision = '5d7a930c439e'
branch_labels = None
depends_on = None

admin = User.ADMIN_ROLE
pentester = User.PENTESTER_ROLE
asset_owner = User.ASSET_OWNER_ROLE
client = User.CLIENT_ROLE

notifications_config = [
    # Host
    {'roles': [admin, pentester, asset_owner, client],
     'event_types': ['new_host', 'update_host', 'delete_host']},
]


def upgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    allowed_roles = sa.table(
        'notification_allowed_roles',
        sa.column('notification_subscription_id', sa.Integer),
        sa.column('allowed_role_id', sa.Integer)
    )
    op.execute("INSERT INTO event_type (name, async_event) VALUES ('new_host', False)")
    op.execute("INSERT INTO event_type (name, async_event) VALUES ('update_host', False)")
    op.execute("INSERT INTO event_type (name, async_event) VALUES ('delete_host', False)")

    res = bind.execute('SELECT name, id FROM event_type').fetchall()  # nosec
    event_type_ids = dict(res)

    res = bind.execute('SELECT name, id FROM faraday_role').fetchall()  # nosec
    role_ids = dict(res)

    for config in notifications_config:
        for event_type in config['event_types']:
            n = NotificationSubscription(event_type_id=event_type_ids[event_type])
            session.add(n)
            session.commit()
            ns = NotificationSubscriptionWebSocketConfig(subscription=n, active=True, role_level=True)
            session.add(ns)
            session.commit()
            for role_name in config['roles']:
                op.execute(
                    allowed_roles.insert().values({'notification_subscription_id': n.id,
                                                   'allowed_role_id': role_ids[role_name]})
                )


def downgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    for config in notifications_config:
        for event_type in config['event_types']:
            event_type_name = session.execute(f"SELECT id "  # nosec
                                              f"FROM event_type e "
                                              f"WHERE e.name = '{event_type}'")
            for event_type_id in event_type_name:
                subscriptions = session.execute(
                    f"SELECT id "  # nosec
                    f"FROM notification_subscription_config_base "
                    f"WHERE subscription_id = '{event_type_id[0]}'")
                for subscription_id in subscriptions:
                    base_config = session.execute(
                        f"SELECT id "  # nosec
                        f"FROM notification_subscription_config_base "
                        f"WHERE subscription_id = '{subscription_id[0]}'")
                    for base_config_id in base_config:
                        session.execute(f"DELETE "  # nosec
                                        f"FROM notification_subscription_websocket_config "
                                        f"WHERE id = '{base_config_id[0]}'")

                        session.execute(f"DELETE "  # nosec
                                        f"FROM notification_allowed_roles na "
                                        f"WHERE na.notification_subscription_id = '{subscription_id[0]}'")

                        session.execute(f"DELETE "  # nosec
                                        f"FROM notification_subscription_config_base "
                                        f"WHERE id = '{base_config_id[0]}'")

                    session.execute(f"DELETE "  # nosec
                                    f"FROM notification_subscription ns "
                                    f"WHERE ns.id = '{subscription_id[0]}'")

        name_list = ",".join([f"'{elem}'" for elem in config["event_types"]])
        session.execute(f'DELETE FROM event_type WHERE name IN ({name_list})')  # nosec
