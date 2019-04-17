# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os

import flask
from flask import Blueprint

from faraday import __version__ as f_version
from faraday.server.config import gen_web_config


info_api = Blueprint('info_api', __name__)

@info_api.route('/v2/info', methods=['GET'])
def show_info():

    response = flask.jsonify({'Faraday Server': 'Running', 'Version': f_version})
    response.status_code = 200

    return response


@info_api.route('/config')
def get_config():
    return flask.jsonify(gen_web_config())

get_config.is_public = True
show_info.is_public = True
