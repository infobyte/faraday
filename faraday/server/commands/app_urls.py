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

from faraday.utils.faraday_openapi_plugin import FaradayAPIPlugin

TAGS = [
        {'name': 'Agents',
         'description': 'Run and manage agents',
         },
        {'name': 'Vulns',
         'description': 'Manage vulnerabilities found',
         },
        {'name': 'Hosts',
         'description': 'Manage hosts',
         },
        {'name': 'Services',
         'description': 'Manage services from hosts',
         },
        ]


def openapi_format(format="yaml"):

    spec = APISpec(
        title="Faraday API",
        version="2",
        openapi_version="3.0.2",
        plugins=[FaradayAPIPlugin(), MarshmallowPlugin()], #FaradayAPIPlugin
        info={'description': 'The Faraday server API'},
        tags=TAGS,
    )

    with app.test_request_context():
        for endpoint in app.view_functions:
            spec.path(view=app.view_functions[endpoint], app=app)
        if format.lower() == "yaml":
            print(spec.to_yaml())
        else:
            print(json.dumps(spec.to_dict(), indent=2))


def show_all_urls():
    print(app.url_map)

# I'm Py3
