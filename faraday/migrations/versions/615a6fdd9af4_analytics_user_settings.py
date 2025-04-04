"""analytics user settings

Revision ID: 615a6fdd9af4
Revises: f2435999bc54
Create Date: 2025-04-01 15:26:42.904208+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '615a6fdd9af4'
down_revision = 'f2435999bc54'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user_notification_settings', sa.Column('analytics_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('user_notification_settings', sa.Column('analytics_app', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('user_notification_settings', sa.Column('analytics_email', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('user_notification_settings', sa.Column('analytics_slack', sa.Boolean(), nullable=False, server_default=sa.text('false')))


def downgrade():
    op.drop_column('user_notification_settings', 'analytics_slack')
    op.drop_column('user_notification_settings', 'analytics_email')
    op.drop_column('user_notification_settings', 'analytics_app')
    op.drop_column('user_notification_settings', 'analytics_enabled')
