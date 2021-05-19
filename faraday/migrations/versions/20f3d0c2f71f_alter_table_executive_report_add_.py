"""Alter table executive_report add advanced_filter_parsed field

Revision ID: 20f3d0c2f71f
Revises: 08d02214aedc
Create Date: 2020-10-04 15:42:43.511069+00:00

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20f3d0c2f71f'
down_revision = '08d02214aedc'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('executive_report',
                  sa.Column(
                      'advanced_filter_parsed',
                      sa.String(255),
                      nullable=False,
                      server_default=""
                  )
                  )


def downgrade():
    op.drop_column('executive_report', 'advanced_filter_parsed')
