"""Add missing start and end columns to rule_execution

Revision ID: 1dbe9e8e4247
Revises: 526aa91cac98
Create Date: 2019-10-03 15:58:56.814375+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1dbe9e8e4247'
down_revision = 'f8a44acd0e41'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('rule_execution',
                  sa.Column(
                      'start',
                      sa.DateTime(), nullable=True
                  )
                  )
    op.add_column('rule_execution',
                  sa.Column(
                      'end',
                      sa.DateTime(), nullable=True
                  )
                  )


def downgrade():
    op.drop_column('rule_execution', 'start')
    op.drop_column('rule_execution', 'end')
