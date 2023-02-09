"""cascade on KB

Revision ID: 1e95dde5b9c8
Revises: f20aa8756612
Create Date: 2023-02-01 21:46:36.071681+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '1e95dde5b9c8'
down_revision = 'f20aa8756612'
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
