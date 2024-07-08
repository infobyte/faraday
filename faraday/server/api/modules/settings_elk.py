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
from faraday.settings.elk import ELKSettingSchema, ELKSettings
from faraday.server.api.modules.settings import SettingsAPIView

logger = logging.getLogger(__name__)
elk_settings_api = Blueprint('elk_settings_api', __name__)

ELKSettingSchema


class ELKSettingsAPI(SettingsAPIView):
    route_base = ELKSettings.settings_id
    schema_class = ELKSettingSchema


ELKSettingsAPI.register(elk_settings_api)
