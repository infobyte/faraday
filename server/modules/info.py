# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask
import os
from server.web import app


@app.route('/info', methods=['GET'])
def show_info():
    faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))

    file_path = os.path.join(faraday_directory, 'VERSION')

    with open(file_path, 'r') as version_file:
        version = version_file.read().strip()

    response = flask.jsonify({'Faraday Server': 'Running', 'Version': version})
    response.status_code = 200

    return response
