# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask, json
import server.database
import server.utils.logger

from server.app import app
from server.utils.web import validate_workspace
from restkit.errors import RequestFailed, ResourceError

logger = server.utils.logger.get_logger(__name__)

def build_bad_request_response(msg):
    response = flask.jsonify({'error': msg})
    response.status_code = 400
    return response

@app.route('/ws/<workspace>/doc/<doc_id>', methods=['GET'])
def get_document(workspace, doc_id):
    validate_workspace(workspace)
    ws =  server.database.get(workspace)
    couchdb_conn = ws.couchdb
    response = couchdb_conn.get_document(doc_id)
    return flask.jsonify(response)

@app.route('/ws/<workspace>/doc/<doc_id>', methods=['PUT'])
def add_or_update_document(workspace, doc_id):
    validate_workspace(workspace)

    try:
        document = json.loads(flask.request.data)
    except ValueError:
        return build_bad_request_response('invalid json')

    document['_id'] = doc_id  # document dictionary does not have id, add it
    ws = server.database.get(workspace)
    couchdb_conn = ws.couchdb
    is_update_request = bool(document.get('_rev', False))

    try:
        response = couchdb_conn.save_doc(document)
    except RequestFailed as e:
        response = flask.jsonify(json.loads(e.msg))
        response.status_code = e.status_int
        return response
    except ResourceError as e:
        response = flask.jsonify({'error': e.message})
        response.status_code = e.status_int
        return response

    if response.get('ok', False):
        doc_importer = server.database.DocumentImporter(ws.connector)
        if is_update_request:
            doc_importer.update_entity_from_doc(document)
        else:
            doc_importer.add_entity_from_doc(document)

    return flask.jsonify(response)

@app.route('/ws/<workspace>/doc/<doc_id>', methods=['DELETE'])
def delete_document(workspace, doc_id):
    validate_workspace(workspace)

    ws = server.database.get(workspace)
    couchdb_conn = ws.couchdb
    doc_rev = flask.request.args.get('rev', '')

    try:
        response = couchdb_conn.delete_doc({'_id': doc_id, '_rev': doc_rev})

    except RequestFailed as e:
        response = flask.jsonify(json.loads(e.msg))
        response.status_code = e.status_int
        return response

    except ResourceError as e:
        response = flask.jsonify({'error': e.message})
        response.status_code = e.status_int
        return response

    if response.get('ok', False):
        doc_importer = server.database.DocumentImporter(ws.connector)
        doc_importer.delete_entity_from_doc_id(doc_id)

    return flask.jsonify(response)
