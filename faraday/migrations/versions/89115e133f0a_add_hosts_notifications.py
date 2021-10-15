"""Add hosts notifications

Revision ID: 89115e133f0a
Revises: 5d7a930c439e
Create Date: 2021-07-26 17:18:43.521015+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
from faraday.server.models import NotificationSubscription, NotificationSubscriptionWebSocketConfig, User, EventType, \
    Role

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

    for config in notifications_config:
        for event_type in config['event_types']:
            roles = session.query(Role).filter(Role.name.in_(config['roles'])).all()
            if not roles:
                raise ValueError(f"Roles {config['roles']} not exist.")

            session.execute(f"INSERT INTO event_type (name) VALUES ('{event_type}')")  # nosec
            event_type_id = session.query(EventType.id).filter(EventType.name == event_type).one()
            n = NotificationSubscription(event_type_id=event_type_id, allowed_roles=roles)

            ns = NotificationSubscriptionWebSocketConfig(subscription=n,
                                                         active=True,
                                                         role_level=True)
            session.add(ns)
            session.commit()


def downgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    for config in notifications_config:
        for event_type in config['event_types']:
            event_type_id = session.query(EventType.id).filter(EventType.name == event_type).one()
            subscription = session.query(NotificationSubscription).filter(NotificationSubscription.event_type_id == event_type_id).one()
            ns = session.query(NotificationSubscriptionWebSocketConfig).filter(NotificationSubscriptionWebSocketConfig.subscription == subscription).one()
            session.delete(ns)
            session.delete(subscription)
            session.commit()
        name_list = ",".join([f"'{elem}'" for elem in config["event_types"]])
        session.execute(f'DELETE FROM event_type WHERE name IN ({name_list})')  # nosec
