"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import validators

# Related third party imports
from marshmallow import fields
from elasticsearch import __version__

# Local application imports
from faraday.server.api.base import AutoSchema
from faraday.settings.base import Settings
from faraday.settings.exceptions import InvalidConfigurationError

DEFAULT_ENABLED = False
DEFAULT_USERNAME = ""
DEFAULT_PASSWORD = ""  # nosec
DEFAULT_HOST = ""
DEFAULT_PORT = 9200
DEFAULT_SENDER = ""
DEFAULT_IGNORE_SSL = False


class ELKSettingSchema(AutoSchema):
    enabled = fields.Boolean(default=DEFAULT_ENABLED, required=True)
    username = fields.String(default=DEFAULT_USERNAME, required=True)
    password = fields.String(default=DEFAULT_PASSWORD, required=True)
    host = fields.String(default=DEFAULT_HOST, required=True)
    port = fields.Integer(default=DEFAULT_PORT, required=True)
    ignore_ssl = fields.Boolean(default=DEFAULT_IGNORE_SSL, required=True)


class ELKSettings(Settings):
    settings_id = "elk"
    settings_key = f'{settings_id}_settings'
    schema = ELKSettingSchema()

    def custom_validation(self, validated_config):
        if validated_config['enabled']:
            for field in ('username', 'password', 'host', 'port'):
                if not validated_config[field]:
                    raise InvalidConfigurationError(f"{field} is required if elk is enabled")
            if __version__[0] < 8 and not validators.url(validated_config['host']):
                raise InvalidConfigurationError("For Python Elasticsearch versions earlier than 8, "
                                                "ensure that the host parameter is a valid URL.")

    def get_default_config(self):
        return {
            'enabled': DEFAULT_ENABLED,
            'username': DEFAULT_USERNAME,
            'password': DEFAULT_PASSWORD,
            'host': DEFAULT_HOST,
            'port': DEFAULT_PORT,
            'ignore_ssl': DEFAULT_IGNORE_SSL
        }


def init_setting():
    ELKSettings()
