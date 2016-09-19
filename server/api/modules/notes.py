# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from flask import request, jsonify, abort

from server.app import app

from server.utils.logger import get_logger
from server.utils.web import gzipped, validate_workspace, filter_request_args

from server.dao.note import NoteDAO


@gzipped
@app.route('/ws/<workspace>/notes', methods=['GET'])
def list_notes(workspace=None):
    
    validate_workspace(workspace)
    get_logger(__name__).debug(
        "Request parameters: {!r}".format(request.args))

    note_filter = filter_request_args()

    dao = NoteDAO(workspace)

    result = dao.list(note_filter=note_filter)

    return jsonify(result)

@app.route('/ws/<workspace>/notes/count', methods=['GET'])
@gzipped
def count_notes(workspace=None):
    validate_workspace(workspace)
    get_logger(__name__).debug("Request parameters: {!r}"\
        .format(request.args))

    services_dao = NoteDAO(workspace)
    result = services_dao.count()
    if result is None:
        abort(400)

    return jsonify(result)