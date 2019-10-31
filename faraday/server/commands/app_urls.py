"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from faraday.server.web import app
from faraday import __version__ as f_version
import json


def openapi_format(format="yaml"):

    spec = APISpec(
        title="faraday",
        version="2.0.0",
        openapi_version="3.0.2",
        plugins=[FlaskPlugin(), MarshmallowPlugin()],
    )

    with app.test_request_context():
        for vv in app.view_functions:
            spec.path(view=app.view_functions[vv])
        if format.lower() == "yaml":
            print(spec.to_yaml())
        else:
            print(json.dumps(spec.to_dict(), indent=2))


def show_all_urls():
    print(app.url_map)

# I'm Py3