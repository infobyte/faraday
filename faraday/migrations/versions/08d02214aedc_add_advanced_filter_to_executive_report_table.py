"""alter executive_report table

Revision ID: 08d02214aedc
Revises: b49d8efbd0c2
Create Date: 2020-09-21 20:42:57.190002+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '08d02214aedc'
down_revision = 'b49d8efbd0c2'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executive_report', sa.Column('advanced_filter', sa.Boolean(), nullable=False, server_default='False'))


def downgrade():
    op.drop_column('executive_report', 'advanced_filter')
