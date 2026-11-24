"""Add cost_usd column to copilot_message_log

Revision ID: 2a3b4c5d6e7f
Revises: 1fe16dbefe9a
Create Date: 2026-09-22
"""
from alembic import op

revision = '2a3b4c5d6e7f'
down_revision = '1fe16dbefe9a'


def upgrade():
    op.execute('ALTER TABLE copilot_message_log '
               'ADD COLUMN IF NOT EXISTS cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0')


def downgrade():
    op.execute('ALTER TABLE IF EXISTS copilot_message_log DROP COLUMN IF EXISTS cost_usd')
