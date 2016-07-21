# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import flask

from server.app import app
from server.dao.host import HostDAO
from server.dao.vuln import VulnerabilityDAO
from server.dao.service import ServiceDAO
from server.dao.interface import InterfaceDAO
from server.dao.note import NoteDAO
from server.utils.web import gzipped, validate_workspace
from server.couchdb import list_workspaces_as_user


@app.route('/ws', methods=['GET'])
@gzipped
def workspace_list():
    return flask.jsonify(list_workspaces_as_user(flask.request.cookies))

@app.route('/ws/<workspace>/summary', methods=['GET'])
@gzipped
def workspace_summary(workspace=None):
    validate_workspace(workspace)

    services_count = ServiceDAO(workspace).count()
    vuln_count = VulnerabilityDAO(workspace).count(vuln_filter=flask.request.args)
    host_count = HostDAO(workspace).count()
    iface_count = InterfaceDAO(workspace).count()
    note_count = NoteDAO(workspace).count()

    response = {
        'stats': {
            'services':    services_count.get('total_count', 0),
            'total_vulns': vuln_count.get('total_count', 0),
            'web_vulns':   vuln_count.get('web_vuln_count', 0),
            'std_vulns':   vuln_count.get('vuln_count', 0),
            'hosts':       host_count.get('total_count', 0),
            'interfaces':  iface_count.get('total_count', 0),
            'notes':       note_count.get('total_count', 0),
        }
    }

    return flask.jsonify(response)

