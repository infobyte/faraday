"""add fields to KB

Revision ID: d9fd2e7aa8dd
Revises: 901344f297fb
Create Date: 2023-11-06 19:36:06.950946+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd9fd2e7aa8dd'
down_revision = '901344f297fb'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('cve_template',
                    sa.Column('id', sa.Integer(), nullable=False),
                    sa.Column('name', sa.String(length=24), nullable=True),
                    sa.Column('year', sa.Integer(), nullable=True),
                    sa.Column('identifier', sa.Integer(), nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    sa.UniqueConstraint('name')
                    )
    op.create_table('cve_template_association',
                    sa.Column('vulnerability_template_id', sa.Integer(), nullable=False),
                    sa.Column('cve_template_id', sa.Integer(), nullable=False),
                    sa.ForeignKeyConstraint(['cve_template_id'], ['cve_template.id'], ),
                    sa.ForeignKeyConstraint(['vulnerability_template_id'], ['vulnerability_template.id'], ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('vulnerability_template_id', 'cve_template_id')
                    )
    op.create_foreign_key('cve_template_association_vulnerability_template_id_fkey',
                          'cve_template_association',
                          'vulnerability_template',
                          ['vulnerability_template_id'],
                          ['id'],
                          ondelete='CASCADE')


def downgrade():
    op.drop_constraint('cve_template_association_vulnerability_template_id_fkey',
                       'cve_template_association', type_='foreignkey')
    op.drop_table('cve_template_association')
    op.drop_table('cve_template')
