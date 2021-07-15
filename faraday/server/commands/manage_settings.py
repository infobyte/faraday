import sys
import click
import json

from faraday.server.web import get_app
from faraday.server.models import (
    db,
    Configuration
)
from faraday.server.utils.database import get_or_create
from faraday.settings import get_settings, get_all_settings, load_settings
from faraday.settings.exceptions import InvalidConfigurationError


def settings_format_validation(ctx, param, value):
    if value is not None:
        try:
            json_data = json.loads(value)
        except json.JSONDecodeError:
            raise click.BadParameter("data must be in json")
        else:
            return json_data


def manage(action, json_data, name):
    load_settings()
    if name:
        name = name.lower()
    available_settings = get_all_settings()
    if action in ('show', 'update'):
        if not name:
            click.secho(f"You must indicate a settings name to {action}", fg="red")
            sys.exit(1)
        else:
            if name not in available_settings:
                click.secho(f'Invalid settings: {name}', fg='red')
                return
        settings = get_settings(name)
        if action == "show":
            click.secho(f"Settings for: {name}", fg="green")
            for key, value in settings.value.items():
                click.secho(f"{key}: {value}")
        elif action == "update":
            new_settings = {}
            click.secho(f"Update settings for: {name}", fg="green")
            for key, value in settings.value.items():
                if json_data is not None:
                    json_value = json_data.get(key, None)
                    if type(json_value) != type(value) or json_value is None:
                        click.secho(f"Missing or Invalid value for {key} [{json_value}]", fg="red")
                        sys.exit(1)
                    else:
                        new_value = json_value
                else:
                    new_value = click.prompt(f'{key}', default=value)
                new_settings[key] = new_value
            try:
                settings.validate_configuration(new_settings)
            except InvalidConfigurationError as e:
                click.secho(f"Invalid configuration for: {name}", fg="red")
                click.secho(e, fg="red")
                sys.exit(1)
            else:
                settings_message = "\n".join([f"{key}: {value}" for key, value in new_settings.items()])
                confirm = json_data is not None
                if not confirm:
                    confirm = click.confirm(f"Do you confirm your changes on {name}?"
                                            f"\n----------------------"
                                            f"\n{settings_message}\n", default=True)
                if confirm:
                    with get_app().app_context():
                        saved_config, created = get_or_create(db.session, Configuration, key=settings.settings_key)
                        if created:
                            saved_config.value = settings.update_configuration(new_settings)
                        else:
                            # SQLAlchemy doesn't detect in-place mutations to the structure of a JSON type.
                            # Thus, we make a deepcopy of the JSON so SQLAlchemy can detect the changes.
                            saved_config.value = settings.update_configuration(new_settings, saved_config.value)
                        db.session.commit()
                        click.secho("Updated!!", fg='green')
                else:
                    click.secho("No changes where made to the settings", fg="green")

    else:
        click.secho("Available settings:", fg="green")
        for i in available_settings:
            click.secho(i)
