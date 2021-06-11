# Faraday Penetration Test IDE
# Copyright (C) 2019  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
from __future__ import absolute_import

import flask
import flask_login
import logging
from flask import Blueprint, abort, make_response
from marshmallow import Schema, fields, ValidationError

from faraday.settings import get_settings, get_all_settings
from faraday.settings.exceptions import InvalidConfigurationError

logger = logging.getLogger(__name__)
settings_api = Blueprint('settings_api', __name__)


class SectionsSchema(Schema):
    sections = fields.List(fields.String(), required=True)


@settings_api.route("/v3/settings", methods=["GET"])
def get_setting_config():
    """
    ---
    get:
      tags: ["Settings"]
      summary: Get setting configuration
      parameters:
        - name: name
          in: query
          description: name of the setting
      responses:
        200:
          description: Ok
        403:
          description: Admin only action
    """
    if flask_login.current_user.role != 'admin':
        abort(403, "Admin only action")

    setting_name = flask.request.args.get('name', None)
    if setting_name is None:
        logger.error(f'Invalid settting: {setting_name}')
        abort(make_response({'message': 'Name required'}, 400))
    settings = get_settings(setting_name)
    if not settings:
        logger.error(f'Invalid settting: {setting_name}')
        abort(make_response({'message': f'Unknown settings [{setting_name}]'}, 404))

    return flask.jsonify(settings.value)


@settings_api.route("/v3/settings/available", methods=["GET"])
def get_available_settings():
    """
    ---
    get:
      tags: ["Settings"]
      summary: Get available settings
      responses:
        200:
          description: Ok
        403:
          description: Admin only action
    """
    if flask_login.current_user.role != 'admin':
        abort(403, "Admin only action")

    available_settings = {'names': get_all_settings()}

    return flask.jsonify(available_settings)


@settings_api.route('/v3/settings', methods=['PUT'])
def update_setting_config():
    """
    ---
    put:
      tags: ["Settings"]
      summary: Update setting configuration
      responses:
        200:
          description: Ok
        403:
          description: Admin only action
    """
    if flask_login.current_user.role != 'admin':
        abort(403, "Admin only action")

    settings_data = flask.request.json
    setting_name = settings_data.pop('name', None)
    settings_config = settings_data.get('value', None)
    if not setting_name or not settings_config:
        logger.error('Missing name or value for settings')
        abort(make_response({'message': 'Missing name or value for settings'}, 400))
    settings = get_settings(setting_name)
    if not settings:
        logger.error(f'Unknown settings [{setting_name}]')
        abort(make_response({'message': f'Unknown settings [{setting_name}]'}, 404))
    logger.info(f"Create or Update settings for: [{setting_name}]")
    try:
        valid_setting_config = settings.validate_configuration(settings_config)
    except (ValidationError, InvalidConfigurationError) as e:
        logger.error(f'Invalid setting for {settings_config}: {e}.')
        abort(make_response({'message': f'{e}.'}, 400))

    settings.update(valid_setting_config)
    return flask.jsonify(settings_config)
