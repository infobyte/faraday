# Faraday Penetration Test IDE
# Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from marshmallow import fields
from pathlib import Path

from faraday.settings.base import Settings
from faraday.settings.exceptions import InvalidConfigurationError
from faraday.server.api.base import AutoSchema

DEFAULT_IGNORE_INFO_SEVERITY = False
DEFAULT_CUSTOM_PLUGINS_FOLDER = ""


class ReportsSettingSchema(AutoSchema):
    ignore_info_severity = fields.Boolean(required=True, default=DEFAULT_IGNORE_INFO_SEVERITY)
    custom_plugins_folder = fields.String(default=DEFAULT_CUSTOM_PLUGINS_FOLDER, required=True)


class ReportsSettings(Settings):
    settings_id = "reports"
    settings_key = f'{settings_id}_settings'
    schema = ReportsSettingSchema()

    def custom_validation(self, validated_config):
        if validated_config['custom_plugins_folder']:
            if validated_config['custom_plugins_folder'] and not Path(validated_config['custom_plugins_folder']).is_dir():
                raise InvalidConfigurationError(f"{validated_config['custom_plugins_folder']} is not valid path")

    def get_default_config(self):
        return {'ignore_info_severity': DEFAULT_IGNORE_INFO_SEVERITY,
                'custom_plugins_folder': DEFAULT_CUSTOM_PLUGINS_FOLDER}


def init_setting():
    ReportsSettings()
