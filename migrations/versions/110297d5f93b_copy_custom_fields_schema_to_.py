"""Copy custom fields schema to vulnerability_template

Revision ID: 110297d5f93b
Revises: 5272b3f5a820
Create Date: 2019-04-22 18:20:34.138566+00:00

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm.session import Session


from faraday.server.models import CustomFieldsSchema

# revision identifiers, used by Alembic.
revision = '110297d5f93b'
down_revision = '1b2533cc16fe'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    session = Session(bind=connection)
    vuln_schemas = connection.execute("""
        SELECT field_name, field_type, field_display_name, field_order, table_name FROM custom_fields_schema
    """)

    for field_name, field_type, field_display_name, field_order, table_name in vuln_schemas:
        vuln_tample_custom_field_schema = CustomFieldsSchema(
            field_name=field_name,
            field_type=field_type,
            field_display_name=field_display_name,
            field_order=field_order,
            table_name='vulnerability_template',
        )
        session.add(vuln_tample_custom_field_schema)

    session.commit()


def downgrade():
    pass
