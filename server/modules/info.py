# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app


@app.route('/info', methods=['GET'])
def show_info():
    response = flask.jsonify({'Faraday Server': 'Running'})
    response.status_code = 200

    return response

