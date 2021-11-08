"""Fix custom fields. display name was used in the key of the json. field_name is expected on the key

Revision ID: 1b2533cc16fe
Revises: 5272b3f5a820
Create Date: 2019-04-05 16:19:11.216571+00:00

"""
import json
from alembic import op
from sqlalchemy.sql import text


# revision identifiers, used by Alembic.
revision = '1b2533cc16fe'
down_revision = '5272b3f5a820'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()

    vulnerabilities = connection.execute("""
        SELECT id, custom_fields FROM vulnerability
    """)

    for vuln_id, custom_fields in vulnerabilities:
        if custom_fields:
            custom_field_schemas = connection.execute("""
                SELECT table_name, field_name, field_type, field_order, field_display_name FROM custom_fields_schema
            """)
            for table_name, field_name, field_type, field_order, field_display_name in custom_field_schemas:

                if table_name == 'vulnerability':
                    if field_display_name not in custom_fields:
                        continue
                    new_data = {field_name: custom_fields[field_display_name]}
                    custom_fields.update(new_data)
                    del custom_fields[field_display_name]
                    connection.execute(text("""
                        UPDATE vulnerability SET custom_fields = :json_data
                            WHERE id = :vuln_id
                    """), **{
                        'json_data': json.dumps(custom_fields),
                        'vuln_id': vuln_id
                    })


def downgrade():
    connection = op.get_bind()

    vulnerabilities = connection.execute("""
        SELECT id, custom_fields FROM vulnerability
    """)

    for vuln_id, custom_fields in vulnerabilities:
        if custom_fields:
            custom_field_schemas = connection.execute("""
                SELECT table_name, field_name, field_type, field_order, field_display_name FROM custom_fields_schema
            """)

            for table_name, field_name, field_type, field_order, field_display_name in custom_field_schemas:
                if table_name == 'vulnerability':
                    if field_name not in custom_fields:
                        continue
                    new_data = {field_display_name: custom_fields[field_name]}
                    custom_fields.update(new_data)
                    del custom_fields[field_name]
                    connection.execute(text("""
                        UPDATE vulnerability SET custom_fields = :json_data
                        WHERE id = :vuln_id
                    """), **{
                        'json_data': json.dumps(custom_fields),
                        'vuln_id': vuln_id
                    })
