"""cascade KB 2

Revision ID: 73854f804a8d
Revises: 61ded0c8fbf6
Create Date: 2023-08-31 17:16:51.813227+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '73854f804a8d'
down_revision = '61ded0c8fbf6'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('ALTER TABLE policy_violation_template_vulnerability_association DROP CONSTRAINT policy_violation_template_vulnerability_a_vulnerability_id_fkey')
    op.execute('ALTER TABLE policy_violation_template_vulnerability_association ADD CONSTRAINT policy_violation_template_vulnerability_a_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_template (id) ON DELETE CASCADE')

    op.execute('ALTER TABLE reference_template_vulnerability_association DROP CONSTRAINT reference_template_vulnerability_associat_vulnerability_id_fkey')
    op.execute('ALTER TABLE reference_template_vulnerability_association ADD CONSTRAINT reference_template_vulnerability_associat_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_template (id) ON DELETE CASCADE')


def downgrade():
    op.execute('ALTER TABLE policy_violation_template_vulnerability_association DROP CONSTRAINT policy_violation_template_vulnerability_a_vulnerability_id_fkey')
    op.execute('ALTER TABLE policy_violation_template_vulnerability_association ADD CONSTRAINT policy_violation_template_vulnerability_a_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_template (id)')

    op.execute('ALTER TABLE reference_template_vulnerability_association DROP CONSTRAINT reference_template_vulnerability_associat_vulnerability_id_fkey')
    op.execute('ALTER TABLE reference_template_vulnerability_association ADD CONSTRAINT reference_template_vulnerability_associat_vulnerability_id_fkey FOREIGN KEY (vulnerability_id) REFERENCES vulnerability_template (id)')
