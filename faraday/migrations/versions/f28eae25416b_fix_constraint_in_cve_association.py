"""Fix constraint in cve association

Revision ID: f28eae25416b
Revises: 1574fbcf72f5
Create Date: 2021-11-04 15:38:26.026998+00:00

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f28eae25416b'
down_revision = '1574fbcf72f5'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('ALTER TABLE cve_association '
               'DROP constraint cve_association_vulnerability_id_fkey, '
               'ADD CONSTRAINT cve_association_vulnerability_id_fkey '
               'FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id) '
               'ON DELETE CASCADE')


def downgrade():
    op.execute('ALTER TABLE cve_association '
               'DROP constraint cve_association_vulnerability_id_fkey, '
               'ADD CONSTRAINT cve_association_vulnerability_id_fkey '
               'FOREIGN KEY (vulnerability_id) REFERENCES vulnerability(id) ')
