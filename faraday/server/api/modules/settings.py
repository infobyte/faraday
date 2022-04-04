"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging

# Related third party imports
import flask
from flask import abort, make_response
from marshmallow import Schema, ValidationError

# Local application imports
from faraday.settings import get_settings
from faraday.settings.exceptions import InvalidConfigurationError
from faraday.server.api.base import GenericView

logger = logging.getLogger(__name__)


class EmptySchema(Schema):
    pass


class SettingsAPIView(GenericView):
    route_prefix = '/v3/settings/'
    schema_class = EmptySchema

    def get(self, **kwargs):
        """
        ---
        get:
          tags: ["settings"]
          summary: Retrieves settings of {route_base}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            403:
              description: Admin user required
        """
        settings = get_settings(self.route_base)
        return self._dump(settings.value, kwargs)

    def patch(self, **kwargs):
        """
        ---
        patch:
          tags: ["settings"]
          summary: Creates/Updates settings of {route_base}
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            403:
              description: Admin user required
        """
        context = {'updating': False}

        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        settings = get_settings(self.route_base)
        try:
            valid_setting_config = settings.validate_configuration(data)
            settings.update(valid_setting_config)
        except (ValidationError, InvalidConfigurationError) as e:
            logger.error(f'Invalid setting for {data}: {e}.')
            abort(make_response({'messages': {'json': {'error': f'{e}.'}}}, 400))
        return self._dump(settings.value, kwargs), 200
