# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import gzip
import functools 
import server.database
import server.couchdb

from flask import after_this_request, request, abort
from cStringIO import StringIO as IO


def get_integer_parameter(query_parameter, default=None):
    param = request.args.get(query_parameter)
    try:
        return int(param) if param is not None else default
    except ValueError:
        abort(400)

def gzipped(f):
    @functools.wraps(f)
    def view_func(*args, **kwargs):
        @after_this_request
        def zipper(response):
            accept_encoding = request.headers.get('Accept-Encoding', '')

            if 'gzip' not in accept_encoding.lower():
                return response

            response.direct_passthrough = False

            if (response.status_code < 200 or
                response.status_code >= 300 or
                'Content-Encoding' in response.headers):
                return response
            gzip_buffer = IO()
            gzip_file = gzip.GzipFile(mode='wb', 
                                      fileobj=gzip_buffer)
            gzip_file.write(response.data)
            gzip_file.close()

            response.data = gzip_buffer.getvalue()
            response.headers['Content-Encoding'] = 'gzip'
            response.headers['Vary'] = 'Accept-Encoding'
            response.headers['Content-Length'] = len(response.data)

            return response

        return f(*args, **kwargs)

    return view_func

def validate_workspace(workspace_name, timeout_sync=0.1):
    if not server.database.is_valid_workspace(workspace_name):
        abort(404)

    if not server.couchdb.has_permissions_for(workspace_name, request.cookies):
        abort(401)

    wait_for_ws_sync_with_couchdb(workspace_name, timeout_sync)

def wait_for_ws_sync_with_couchdb(workspace_name, timeout_sync):
    workspace = server.database.get(workspace_name)
    workspace.wait_until_sync(timeout_sync)

