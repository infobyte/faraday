"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import functools
import gzip
from io import BytesIO as IO

# Related third party imports
from flask import after_this_request, request, abort, jsonify


def get_integer_parameter(query_parameter, default=None):
    """Obtains an integer parameter and ensures its type"""
    param = request.args.get(query_parameter)
    try:
        return int(param) if param is not None else default
    except ValueError:
        abort(400)


def get_mandatory_integer_parameter(query_parameter):
    """Obtains an integer parameter and ensures its type, if it can't
    will raise an 400 response"""
    param = request.args[query_parameter]
    try:
        return int(param)
    except ValueError:
        abort(400)


def filter_request_args(*filter_out_args):
    filtered_args = {}
    for arg in request.args:
        if arg not in filter_out_args:
            filtered_args[arg] = request.args.get(arg)
    return filtered_args


def gzipped(f):
    """Decorates a flask request function to return a gzipped response"""
    @functools.wraps(f)
    def view_func(*args, **kwargs):
        @after_this_request
        def zipper(response):  # pylint:disable=unused-variable
            accept_encoding = request.headers.get('Accept-Encoding', '')

            if 'gzip' not in accept_encoding.lower():
                return response

            response.direct_passthrough = False

            if (response.status_code < 200
                    or response.status_code >= 300
                    or 'Content-Encoding' in response.headers):
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


def get_basic_auth():
    if request.authorization:
        user, passwd = request.authorization.get('username'), request.authorization.get('password')
        if (all((user, passwd))):
            return (user, passwd)
    return None


def build_bad_request_response(msg):
    response = jsonify({'error': msg})
    response.status_code = 400
    return response
