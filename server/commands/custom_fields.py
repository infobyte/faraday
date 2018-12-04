import sys
import click

from server.web import app
from server.models import (
    db,
    CustomFieldsSchema
)
from server.utils.database import get_or_create


def add_custom_field_main():
    with app.app_context():
        add_custom_field_wizard()


def add_custom_field_wizard():
    print('This wizard will guide you to add custom field to the vulneraiblity model.')
    field_name = click.prompt('Field name')
    field_display_name = click.prompt('Display name')
    field_type = click.prompt('Field type (int, str, list)', type=click.Choice(['int', 'str', 'list']))
    confirmation = click.prompt('New CustomField will be added to vulnerability -> ({0},{1},{2}) <-, confirm to continue (yes/no)'.format(field_name, field_display_name, field_type))
    if not confirmation:
        sys.exit(1)

    custom_field_data, created = get_or_create(
            db.session,
            CustomFieldsSchema,
            table_name='vulnerability',
            field_name=field_name,
    )
    if not created:
        print('Custom field already exists, skipping')
        sys.exit(1)
    custom_field_data.field_display_name = field_display_name,
    custom_field_data.field_type = field_type
    db.session.commit()
