"""add fields to KB

Revision ID: 257f6d0ad43f
Revises: b87b1de2f348
Create Date: 2023-11-10 21:47:36.973846+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '257f6d0ad43f'
down_revision = 'b87b1de2f348'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('vulnerability_template',
                  sa.Column('cve', sa.Text(), default='', server_default='', nullable=True))
    op.add_column('vulnerability_template',
                  sa.Column('_cvss2_vector_string', sa.Text(), default='', server_default='', nullable=True))
    op.add_column('vulnerability_template',
                  sa.Column('_cvss3_vector_string', sa.Text(), default='', server_default='', nullable=True))


def downgrade():
    op.drop_column('vulnerability_template', 'cve')
    op.drop_column('vulnerability_template', '_cvss2_vector_string')
    op.drop_column('vulnerability_template', '_cvss3_vector_string')
