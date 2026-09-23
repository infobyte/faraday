"""ws_sum_reports user settings

Revision ID: 59bf674e5b99
Revises: 7981b912d520
Create Date: 2026-07-31 00:00:02.000000+00:00

"""
from alembic import op
import sqlalchemy as sa


revision = '59bf674e5b99'
down_revision = '7981b912d520'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('user_notification_settings', sa.Column('ws_sum_reports_enabled', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('user_notification_settings', sa.Column('ws_sum_reports_app', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    op.add_column('user_notification_settings', sa.Column('ws_sum_reports_email', sa.Boolean(), nullable=False, server_default=sa.text('false')))
    op.add_column('user_notification_settings', sa.Column('ws_sum_reports_slack', sa.Boolean(), nullable=False, server_default=sa.text('false')))


def downgrade():
    op.drop_column('user_notification_settings', 'ws_sum_reports_slack')
    op.drop_column('user_notification_settings', 'ws_sum_reports_email')
    op.drop_column('user_notification_settings', 'ws_sum_reports_app')
    op.drop_column('user_notification_settings', 'ws_sum_reports_enabled')
