"""disable several notifications and add event enabled flag

Revision ID: 1574fbcf72f5
Revises: 89115e133f0a
Create Date: 2021-09-21 13:46:08.382496+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
from faraday.server.models import NotificationSubscription, EventType, NotificationSubscriptionWebSocketConfig

revision = '1574fbcf72f5'
down_revision = '89115e133f0a'
branch_labels = None
depends_on = None

enabled_notifications = ['new_workspace', 'update_executivereport', 'new_agentexecution', 'new_command', 'new_comment']


def upgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    session.execute("ALTER TABLE event_type ADD COLUMN enabled BOOLEAN DEFAULT true")
    session.commit()

    events = session.query(EventType).filter(EventType.name.notin_(enabled_notifications)).all()
    for event in events:
        event.enabled = False

    notifications = session.query(NotificationSubscriptionWebSocketConfig)\
        .join(NotificationSubscription).join(EventType).filter(EventType.name.notin_(enabled_notifications)).all()
    for notification in notifications:
        notification.active = False
        session.add(notification)
    session.commit()


def downgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    op.execute("ALTER TABLE event_type DROP COLUMN enabled")

    notifications = session.query(NotificationSubscriptionWebSocketConfig)\
        .join(NotificationSubscription).join(EventType).filter(EventType.name.notin_(enabled_notifications)).all()
    for notification in notifications:
        notification.active = True
    session.commit()
