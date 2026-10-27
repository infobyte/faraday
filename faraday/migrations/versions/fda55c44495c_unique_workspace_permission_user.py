"""unique (workspace_id, user_id) on workspace_permission_association

Revision ID: fda55c44495c
Revises: a0b302b596ac
Create Date: 2026-10-27 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'fda55c44495c'
down_revision = 'a0b302b596ac'
branch_labels = None
depends_on = None

CONSTRAINT_NAME = 'uix_workspace_permission_workspace_user'


def upgrade():
    op.execute(
        """
        DELETE FROM workspace_permission_association a
        USING workspace_permission_association b
        WHERE a.workspace_id = b.workspace_id
          AND a.user_id = b.user_id
          AND a.id > b.id
        """
    )
    op.execute(f'ALTER TABLE workspace_permission_association DROP CONSTRAINT IF EXISTS {CONSTRAINT_NAME}')
    op.execute(
        f'ALTER TABLE workspace_permission_association '
        f'ADD CONSTRAINT {CONSTRAINT_NAME} UNIQUE (workspace_id, user_id)'
    )


def downgrade():
    op.execute(f'ALTER TABLE workspace_permission_association DROP CONSTRAINT IF EXISTS {CONSTRAINT_NAME}')
