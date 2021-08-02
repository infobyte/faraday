"""Add hosts notifications

Revision ID: 89115e133f0a
Revises: a9fcf8444c79
Create Date: 2021-07-26 17:18:43.521015+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
from faraday.server.models import NotificationSubscription, NotificationSubscriptionWebSocketConfig, User, EventType, \
    Role

revision = '89115e133f0a'
down_revision = 'a9fcf8444c79'
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
            event_type_obj = EventType(name=event_type)
            n = NotificationSubscription(event_type=event_type_obj, allowed_roles=roles)
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
            event_type_objs = session.query(EventType).filter(EventType.name == event_type).all()
            for event_type_obj in event_type_objs:
                session.delete(event_type_obj)
                session.commit()
