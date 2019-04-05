"""Fix custom fields. display name was used in the key of the json. field_name is expected on the key

Revision ID: 1b2533cc16fe
Revises: 5272b3f5a820
Create Date: 2019-04-05 16:19:11.216571+00:00

"""
import json
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1b2533cc16fe'
down_revision = '5272b3f5a820'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()

    custom_fields = connection.execute("""
        SELECT * FROM custom_fields_schema
    """)
    vulnerabilities = connection.execute("""
        SELECT id, custom_fields FROM vulnerability
    """)

    for custom_field_schema in custom_fields:
        if custom_field_schema[1] == 'vulnerability':
            field_name = custom_field_schema[2]
            display_name = custom_field_schema[5]
            for vuln in vulnerabilities:
                vuln_id = vuln[0]
                if vuln[1]:
                    new_data = {field_name: vuln[1][display_name]}
                    connection.execute("""
                        UPDATE vulnerability SET custom_fields='{0}' WHERE id={1}
                    """.format(json.dumps(new_data), vuln_id))


def downgrade():
    connection = op.get_bind()

    custom_fields = connection.execute("""
        SELECT * FROM custom_fields_schema
    """)
    vulnerabilities = connection.execute("""
        SELECT id, custom_fields FROM vulnerability
    """)

    for custom_field_schema in custom_fields:
        if custom_field_schema[1] == 'vulnerability':
            field_name = custom_field_schema[2]
            display_name = custom_field_schema[5]
            import pdb; pdb.set_trace()
            for vuln in vulnerabilities:
                vuln_id = vuln[0]
                if vuln[1]:
                    new_data = {display_name: vuln[1][display_name]}
                    connection.execute("""
                        UPDATE vulnerability SET custom_fields='{0}' WHERE id={1}
                    """.format(json.dumps(new_data), vuln_id))

