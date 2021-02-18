"""add enum to comment model

Revision ID: d3afdb4e0b11
Revises: 5658775e113f
Create Date: 2021-02-01 14:43:49.849647+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd3afdb4e0b11'
down_revision = '5658775e113f'
branch_labels = None
depends_on = None


def upgrade():
    op.execute("CREATE TYPE comment_types AS ENUM('system', 'user')")
    op.add_column('comment', sa.Column(
        'comment_type',
        sa.Enum(('system', 'user'), name='comment_types'),
        nullable=False,
        server_default='user',
        default='user'))


def downgrade():
    op.drop_column('comment', 'comment_type')
    op.execute('DROP TYPE comment_types')
