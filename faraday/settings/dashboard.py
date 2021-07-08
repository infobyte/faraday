# Faraday Penetration Test IDE
# Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from marshmallow import fields

from faraday.settings.base import Settings
from faraday.server.api.base import AutoSchema

DEFAULT_SHOW_VULNS_BY_PRICE = False


class DashboardSettingSchema(AutoSchema):
    show_vulns_by_price = fields.Boolean(default=DEFAULT_SHOW_VULNS_BY_PRICE, required=True)


class DashboardSettings(Settings):
    settings_id = "dashboard"
    settings_key = f'{settings_id}_settings'
    schema = DashboardSettingSchema()

    def get_default_config(self):
        return {'show_vulns_by_price': DEFAULT_SHOW_VULNS_BY_PRICE}


def init_setting():
    DashboardSettings()
