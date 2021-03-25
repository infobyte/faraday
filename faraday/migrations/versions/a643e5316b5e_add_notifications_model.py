"""add notifications model

Revision ID: a643e5316b5e
Revises: 6471033046cb
Create Date: 2021-02-24 15:43:13.950912+00:00

"""
from datetime import datetime

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a643e5316b5e'
down_revision = '6471033046cb'
branch_labels = None
depends_on = None

NOTIFICATION_METHODS = [
    'mail',
    'webhook',
    'websocket'
]

NOTIFICATION_EVENTS = [
    'new_workspace',
    'new_agent',
    'new_user',
    'new_agent_scan',
    'new_report_scan',
    'new_vulnerability'
]

OBJECT_TYPES = (
    'vulnerability',
    'host',
    'credential',
    'service',
    'source_code',
    'comment',
    'executive_report',
    'workspace',
    'task'
    )


def upgrade():
    op.create_table(
        'notification_method',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('method', sa.Enum(*NOTIFICATION_METHODS, name='notification_methods'), nullable=False),
        sa.Column('method_configuration', sa.String, nullable=False),
        sa.Column('user_notified_id', sa.Integer),
    )

    op.create_table(
        'notification_config',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('event', sa.Enum(*NOTIFICATION_EVENTS, name='notification_events'), nullable=False),
        sa.Column('method_id', sa.Integer),
        sa.Column('active', sa.Boolean(), default=True)
    )

    op.create_table(
        'notification_event',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('event', sa.Enum(*NOTIFICATION_EVENTS, name='notification_events'), nullable=False),
        sa.Column('object_id', sa.Integer),
        sa.Column('notification_data', sa.JSON, nullable=False),
        sa.Column('create_date', sa.DateTime(), default=datetime.now()),
    )

    op.add_column('notification_event',
        sa.Column(
            'object_type',
            sa.Enum(OBJECT_TYPES, name='object_types'),
            nullable=False
        )
    )

    op.create_table(
        'notification2',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('event_id', sa.Integer),
        sa.Column('config_id', sa.Integer),
        sa.Column('mark_read', sa.Boolean),
        # sa.Column('notification_text', sa.String(256), nullable=False)
    )

    op.create_foreign_key(
        'notification_config_method_id_fkey',
        'notification_config',
        'notification_method', ['method_id'], ['id']
    )

    op.create_foreign_key(
        'notification_method_user_notified_id_fkey',
        'notification_method',
        'faraday_user', ['user_notified_id'], ['id']
    )

    op.create_foreign_key(
        'notification2_event_id_fkey',
        'notification2',
        'notification_event', ['event_id'], ['id']
    )

    op.create_foreign_key(
        'notification2_config_id_fkey',
        'notification2',
        'notification_config', ['config_id'], ['id']
    )

def downgrade():
    op.drop_table('notification2')
    op.drop_table('notification_event')
    op.drop_table('notification_config')
    op.drop_table('notification_method')
    op.execute('DROP TYPE notification_events')
    op.execute('DROP TYPE notification_methods')
