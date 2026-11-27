"""Add cache token columns to copilot_message_log

Revision ID: 1fe16dbefe9a
Revises: a1b2c3d4e5f6
Create Date: 2026-09-21
"""
from alembic import op

revision = '1fe16dbefe9a'
down_revision = 'a1b2c3d4e5f6'


def upgrade():
    op.execute('ALTER TABLE copilot_message_log '
               'ADD COLUMN IF NOT EXISTS cache_read_tokens INTEGER NOT NULL DEFAULT 0, '
               'ADD COLUMN IF NOT EXISTS cache_write_tokens INTEGER NOT NULL DEFAULT 0')


def downgrade():
    op.execute('ALTER TABLE IF EXISTS copilot_message_log '
               'DROP COLUMN IF EXISTS cache_write_tokens, '
               'DROP COLUMN IF EXISTS cache_read_tokens')
