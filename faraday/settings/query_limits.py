"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Related third party imports
from marshmallow import fields

# Local application imports
from faraday.server.api.base import AutoSchema
from faraday.settings.base import Settings

DEFAULT_VULN_LIMIT = 0


class QueryLimitsSchema(AutoSchema):
    vuln_query_limit = fields.Int(default=DEFAULT_VULN_LIMIT, required=True, validate=lambda x: x >= 0)


class QueryLimitsSettings(Settings):
    settings_id = "query_limits"
    settings_key = f'{settings_id}_settings'
    schema = QueryLimitsSchema()

    def get_default_config(self):
        return {'vuln_query_limit': DEFAULT_VULN_LIMIT}


def init_setting():
    QueryLimitsSettings()
