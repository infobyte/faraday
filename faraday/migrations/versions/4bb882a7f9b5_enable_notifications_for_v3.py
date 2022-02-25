"""enable notifications for v3

Revision ID: 4bb882a7f9b5
Revises: 5cf9660bba80
Create Date: 2022-02-25 14:24:20.027512+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '4bb882a7f9b5'
down_revision = 'cb25cf42bda7'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('UPDATE  NOTIFICATION_SUBSCRIPTION_CONFIG_BASE SET active = true WHERE id IN (1, 11, 14, 21, 13)')


def downgrade():
    # we will not downgrade this change.
    pass
