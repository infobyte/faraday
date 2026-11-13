"""Add copilot_message_log table and user copilot_enabled

Revision ID: a1b2c3d4e5f6
Revises: d7a3e9b1c5f2
Create Date: 2026-09-01
"""
from alembic import op

revision = 'a1b2c3d4e5f6'
down_revision = 'd7a3e9b1c5f2'


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS copilot_message_log (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES faraday_user (id),
            workspace_name TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
            user_message TEXT NOT NULL,
            assistant_reply TEXT,
            tool_calls JSONB,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            model_id TEXT,
            status TEXT NOT NULL DEFAULT 'success',
            error_message TEXT
        )
    """)
    op.execute('CREATE INDEX IF NOT EXISTS ix_copilot_message_log_user_id ON copilot_message_log (user_id)')
    op.execute('CREATE INDEX IF NOT EXISTS ix_copilot_message_log_created_at ON copilot_message_log (created_at)')
    op.execute('ALTER TABLE faraday_user ADD COLUMN IF NOT EXISTS copilot_enabled BOOLEAN NOT NULL DEFAULT false')
    # Admins get the copilot by default, as new and promoted admins do.
    op.execute("""
        UPDATE faraday_user SET copilot_enabled = true
        WHERE id IN (
            SELECT roles_users.user_id FROM roles_users
            JOIN faraday_role ON faraday_role.id = roles_users.role_id
            WHERE faraday_role.name = 'admin'
        )
    """)


def downgrade():
    op.execute('ALTER TABLE faraday_user DROP COLUMN IF EXISTS copilot_enabled')
    op.execute('DROP TABLE IF EXISTS copilot_message_log')
