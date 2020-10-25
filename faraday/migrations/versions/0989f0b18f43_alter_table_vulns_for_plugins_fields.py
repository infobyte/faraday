"""alter_table_vulns_for_plugins_fields

Revision ID: 0989f0b18f43
Revises: 160472206b7c
Create Date: 2020-10-25 12:12:46.087503+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0989f0b18f43'
down_revision = '160472206b7c'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('vulnerability', 'cvss')
    op.drop_column('vulnerability', 'cwe')

    op.add_column('vulnerability',
                  sa.Column(
                      'cvss_v2',
                      sa.Text,
                      nullable=True
                  )
    )


    op.add_column('vulnerability',
                  sa.Column(
                      'cvss_v3',
                      sa.Text,
                      nullable=True
                  )
    )



def downgrade():
    op.drop_column('vulnerability', 'cvss_v2')
    op.drop_column('vulnerability', 'cvss_v3')
    op.add_column('vulnerability',
                  sa.Column(
                      'cvss',
                      sa.Text,
                      nullable=True
                  )
    )

    op.add_column('vulnerability',
                  sa.Column(
                      'cwe',
                      sa.Text,
                      nullable=True
                  )
    )

