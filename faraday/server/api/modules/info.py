# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
from flask import Blueprint

from faraday import __version__ as f_version
from faraday.server.config import faraday_server
from faraday.settings.dashboard import DashboardSettings

info_api = Blueprint('info_api', __name__)


@info_api.route('/v3/info', methods=['GET'])
def show_info():
    """
    ---
    get:
      tags: ["Informational"]
      description: Gives basic info about the faraday service
      responses:
        200:
          description: Ok
    """

    response = flask.jsonify({'Faraday Server': 'Running', 'Version': f_version})
    response.status_code = 200

    return response


@info_api.route('/config')
def get_config():
    """
    ---
    get:
      tags: ["Informational"]
      description: Gives basic info about the faraday configuration
      responses:
        200:
          description: Ok
    """
    doc = {
        'ver': f_version,
        'websocket_port': faraday_server.websocket_port,
        'show_vulns_by_price': DashboardSettings.settings.show_vulns_by_price,
        'smtp_enabled': False
    }

    return flask.jsonify(doc)


get_config.is_public = True
show_info.is_public = True
