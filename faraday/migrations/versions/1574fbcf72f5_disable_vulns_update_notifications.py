"""disable vulns update notifications

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


def upgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    # Disable update_vulnerability event
    n = session.query(NotificationSubscriptionWebSocketConfig).join(NotificationSubscription).join(EventType).filter(EventType.name == 'update_vulnerability').one()
    n.active = False
    session.add(n)
    session.commit()

    # Disable update_vulnerability_web event
    n = session.query(NotificationSubscriptionWebSocketConfig).join(NotificationSubscription).join(EventType).filter(EventType.name == 'update_vulnerabilityweb').one()
    n.active = False
    session.add(n)
    session.commit()


def downgrade():
    bind = op.get_bind()
    session = sa.orm.Session(bind=bind)

    # Enable update_vulnerability event
    n = session.query(NotificationSubscriptionWebSocketConfig).join(NotificationSubscription).join(EventType).filter(EventType.name == 'update_vulnerability').one()
    n.active = True
    session.add(n)
    session.commit()

    # Enable update_vulnerability_web event
    n = session.query(NotificationSubscriptionWebSocketConfig).join(NotificationSubscription).join(EventType).filter(EventType.name == 'update_vulnerabilityweb').one()
    n.active = True
    session.add(n)
    session.commit()
