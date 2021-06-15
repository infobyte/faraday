# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from __future__ import absolute_import

import flask
import flask_login
import logging
from flask import abort, make_response
from marshmallow import Schema, ValidationError

from faraday.settings import get_settings
from faraday.settings.exceptions import InvalidConfigurationError

from faraday.server.api.base import (
    GenericView
)

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
          summary: Retrieves settings
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            403:
              description: Admin user required
        """
        if flask_login.current_user.role != 'admin':
            abort(403, "Admin only action")

        settings = get_settings(self.route_base)
        return self._dump(settings.value, kwargs)

    def post(self, **kwargs):
        """
        ---
        post:
          tags: ["settings"]
          summary: Creates/Updates settings
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            403:
              description: Admin user required
        """
        if flask_login.current_user.role != 'admin':
            abort(403, "Admin only action")

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
        return self._dump(settings.value, kwargs), 201
