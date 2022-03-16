"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging

# Related third party imports
from flask import Blueprint

# Local application imports
from faraday.settings.dashboard import DashboardSettingSchema, DashboardSettings
from faraday.server.api.modules.settings import SettingsAPIView

logger = logging.getLogger(__name__)
dashboard_settings_api = Blueprint('dashboard_settings_api', __name__)


class DashboardSettingsAPI(SettingsAPIView):
    route_base = DashboardSettings.settings_id
    schema_class = DashboardSettingSchema


DashboardSettingsAPI.register(dashboard_settings_api)
