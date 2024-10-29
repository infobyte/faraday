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
from faraday.settings.query_limits import QueryLimitsSchema, QueryLimitsSettings
from faraday.server.api.modules.settings import SettingsAPIView

logger = logging.getLogger(__name__)
query_limits_settings_api = Blueprint('query_limits_settings_api', __name__)

QueryLimitsSchema


class QueryLimitsSettingsAPI(SettingsAPIView):
    route_base = QueryLimitsSettings.settings_id
    schema_class = QueryLimitsSchema


QueryLimitsSettingsAPI.register(query_limits_settings_api)
