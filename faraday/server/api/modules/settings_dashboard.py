# Faraday Penetration Test IDE
# Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import logging
from flask import Blueprint

from faraday.settings.dashboard import DashboardSettingSchema, DashboardSettings
from faraday.server.api.modules.settings import SettingsAPIView

logger = logging.getLogger(__name__)
dashboard_settings_api = Blueprint('dashboard_settings_api', __name__)


class DashboardSettingsAPI(SettingsAPIView):
    route_base = DashboardSettings.settings_id
    schema_class = DashboardSettingSchema


DashboardSettingsAPI.register(dashboard_settings_api)
