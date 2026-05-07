"""add unique constraint to the vuln-credential association table

Revision ID: b3e7f1a2c904
Revises: 22321da63ce6
Create Date: 2026-05-07 00:00:00.000000+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'b3e7f1a2c904'
down_revision = '22321da63ce6'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        op.execute("""
            DELETE FROM association_table_vulnerabilities_credentials a
            USING association_table_vulnerabilities_credentials b
            WHERE a.ctid > b.ctid
              AND a.vulnerability_id = b.vulnerability_id
              AND a.credential_id = b.credential_id
        """)
    else:
        op.execute("""
            DELETE FROM association_table_vulnerabilities_credentials
            WHERE rowid NOT IN (
                SELECT MIN(rowid)
                FROM association_table_vulnerabilities_credentials
                GROUP BY vulnerability_id, credential_id
            )
        """)
    op.create_unique_constraint(
        'uix_vuln_cred_pair',
        'association_table_vulnerabilities_credentials',
        ['vulnerability_id', 'credential_id']
    )


def downgrade():
    op.drop_constraint(
        'uix_vuln_cred_pair',
        'association_table_vulnerabilities_credentials',
        type_='unique'
    )
