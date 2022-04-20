"""comment ws not mandatory

Revision ID: 877dd088c8cb
Revises: 1d328f7bf643
Create Date: 2022-03-22 16:23:59.091968+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '877dd088c8cb'
down_revision = '1d328f7bf643'
branch_labels = None
depends_on = None


def upgrade():
    if not op.get_context().as_sql:
        connection = op.get_bind()
        connection.execution_options(isolation_level='AUTOCOMMIT')
    op.alter_column('comment', 'workspace_id', nullable=True)
    op.execute("ALTER TYPE object_types ADD VALUE IF NOT EXISTS 'project_task'")


def downgrade():
    op.execute("DELETE FROM comment WHERE object_type = 'project_task'")
    op.alter_column('comment', 'workspace_id', nullable=False)
