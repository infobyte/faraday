# Faraday Penetration Test IDE
# Copyright (C) 2021  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import logging
from flask import Blueprint

from faraday.settings.reports import ReportsSettingSchema, ReportsSettings
from faraday.server.api.modules.settings import SettingsAPIView

logger = logging.getLogger(__name__)
reports_settings_api = Blueprint('reports_settings_api', __name__)


class ReportsSettingsAPI(SettingsAPIView):
    route_base = ReportsSettings.settings_id
    schema_class = ReportsSettingSchema


ReportsSettingsAPI.register(reports_settings_api)
