"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
from pathlib import Path

# Related third party imports
from marshmallow import fields

# Local application imports
from faraday.server.api.base import AutoSchema
from faraday.settings.base import Settings
from faraday.settings.exceptions import InvalidConfigurationError

DEFAULT_CUSTOM_PLUGINS_FOLDER = ""


class ReportsSettingSchema(AutoSchema):
    custom_plugins_folder = fields.String(default=DEFAULT_CUSTOM_PLUGINS_FOLDER, required=True)


class ReportsSettings(Settings):
    settings_id = "reports"
    settings_key = f'{settings_id}_settings'
    schema = ReportsSettingSchema()

    def custom_validation(self, validated_config):
        if validated_config['custom_plugins_folder']:
            if validated_config['custom_plugins_folder'] and \
                    not Path(validated_config['custom_plugins_folder']).is_dir():
                raise InvalidConfigurationError(f"{validated_config['custom_plugins_folder']} is not valid path")

    def get_default_config(self):
        return {'custom_plugins_folder': DEFAULT_CUSTOM_PLUGINS_FOLDER}


def init_setting():
    ReportsSettings()
