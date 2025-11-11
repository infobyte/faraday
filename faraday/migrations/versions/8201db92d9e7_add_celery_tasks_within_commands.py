"""add_celery_tasks_within_commands

Revision ID: 8201db92d9e7
Revises: c49e0cb49483
Create Date: 2025-11-10 14:29:08.391842+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8201db92d9e7'
down_revision = 'c49e0cb49483'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('command', sa.Column('tasks', sa.JSON, nullable=True))


def downgrade():
    op.drop_column('command', 'tasks')
