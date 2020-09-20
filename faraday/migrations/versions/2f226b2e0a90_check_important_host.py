"""check important host

Revision ID: 2f226b2e0a90
Revises: b49d8efbd0c2
Create Date: 2020-09-19 21:40:57.444782+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2f226b2e0a90'
down_revision = 'b49d8efbd0c2'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('host', sa.Column('mark_important', sa.Boolean(), nullable=False, server_default='False'))


def downgrade():
    op.drop_column('host', 'mark_important')
