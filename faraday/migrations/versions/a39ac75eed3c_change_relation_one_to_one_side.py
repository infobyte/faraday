"""Change relation one to one side

Revision ID: a39ac75eed3c
Revises: 5cf9660bba80
Create Date: 2021-12-29 13:17:55.131029+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a39ac75eed3c'
down_revision = '5cf9660bba80'
branch_labels = None
depends_on = None


def upgrade():
    # Drop Vuln <- cvss
    op.drop_constraint('vulnerability_cvssv2_id_fkey', 'vulnerability', type_='foreignkey')
    op.drop_constraint('vulnerability_cvssv3_id_fkey', 'vulnerability', type_='foreignkey')
    op.drop_column('vulnerability', 'cvssv2_id')
    op.drop_column('vulnerability', 'cvssv3_id')

    # Vuln -> cvss
    op.add_column('cvss_v2', sa.Column('vulnerability_id', sa.Integer(), nullable=True))
    op.add_column('cvss_v3', sa.Column('vulnerability_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'cvss_v2', 'vulnerability', ['vulnerability_id'], ['id'])
    op.create_foreign_key(None, 'cvss_v3', 'vulnerability', ['vulnerability_id'], ['id'])


def downgrade():
    op.drop_constraint('cvss_v2_vulnerability_id_fkey', 'cvss_v2', type_='foreignkey')
    op.drop_constraint('cvss_v3_vulnerability_id_fkey', 'cvss_v3', type_='foreignkey')
    op.drop_column('cvss_v2', 'vulnerability_id')
    op.drop_column('cvss_v3', 'vulnerability_id')

    op.add_column('vulnerability', sa.Column('cvssv2_id', sa.Integer(), nullable=True))
    op.add_column('vulnerability', sa.Column('cvssv3_id', sa.Integer(), nullable=True))
    op.create_foreign_key(None, 'vulnerability', 'cvss_v2', ['cvssv2_id'], ['id'])
    op.create_foreign_key(None, 'vulnerability', 'cvss_v3', ['cvssv3_id'], ['id'])
