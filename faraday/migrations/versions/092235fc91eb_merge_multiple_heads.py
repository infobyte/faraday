"""merge_multiple_heads

Revision ID: 092235fc91eb
Revises: 2a0de6132377, 904a517a2f0c
Create Date: 2019-11-20 18:23:24.509540+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '092235fc91eb'
down_revision = ('2a0de6132377', '904a517a2f0c')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
