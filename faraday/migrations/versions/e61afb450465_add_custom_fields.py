"""Add custom fields

Revision ID: e61afb450465
Revises:
Create Date: 2018-10-23 15:43:52.612619+00:00

"""
from alembic import op


# revision identifiers, used by Alembic.
revision = 'e61afb450465'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE vulnerability ADD COLUMN custom_fields JSONB')
    conn.execute('ALTER TABLE vulnerability_template ADD COLUMN custom_fields JSONB')
    conn.execute('CREATE TABLE custom_fields_schema ( '
                 'id SERIAL PRIMARY KEY,'
                 'table_name TEXT,'
                 'field_name TEXT,'
                 'field_type TEXT,'
                 'field_order INTEGER,'
                 'field_display_name TEXT)'
                 )


def downgrade():
    conn = op.get_bind()
    conn.execute('ALTER TABLE vulnerability DROP COLUMN custom_fields')
    conn.execute('ALTER TABLE vulnerability_template DROP COLUMN custom_fields')
    conn.execute('DROP TABLE custom_fields_schema')
