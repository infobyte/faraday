"""unique field_name in CustomField

Revision ID: 2db31733fb78
Revises: 0d216660da28
Create Date: 2019-05-15 18:48:41.909650+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = '2db31733fb78'
down_revision = '0d216660da28'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE custom_fields_schema ADD UNIQUE (field_name)')


def downgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE custom_fields_schema DROP CONSTRAINT custom_fields_schema_field_name_key;')
