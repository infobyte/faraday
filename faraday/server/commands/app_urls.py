"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
from pathlib import Path

import yaml
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from faraday.server.web import get_app
from faraday import __version__ as f_version
import json
from urllib.parse import urljoin
from faraday.server.config import LOCAL_OPENAPI_FILE

from faraday.utils.faraday_openapi_plugin import FaradayAPIPlugin


def openapi_format(server, modify_default=False, return_tags=False):
    extra_specs = {'info': {
        'description': 'The Faraday REST API enables you to interact with '
                       '[our server](https://github.com/infobyte/faraday).\n'
                       'Use this API to interact or integrate with Faraday'
                       ' server. This page documents the REST API, with HTTP'
                       ' response codes and example requests and responses.'},
        'security': {"basicAuth": []}
    }

    if not server.startswith('http'):
        raise ValueError('Server must be an http url')

    server = urljoin(server, "/_api")

    extra_specs['servers'] = [{'url': server}]

    spec = APISpec(
        title=f"Faraday {f_version} API",
        version="v3",
        openapi_version="3.0.2",
        plugins=[FaradayAPIPlugin(), FlaskPlugin(), MarshmallowPlugin()],
        **extra_specs
    )
    auth_scheme = {
        "type": "http",
        "scheme": "Basic"
    }

    spec.components.security_scheme("basicAuth", auth_scheme)
    response_401_unauthorized = {
        "description": "You are not authenticated or your API key is missing "
                       "or invalid"
    }
    spec.components.response("UnauthorizedError", response_401_unauthorized)

    tags = set()

    with get_app().test_request_context():
        for endpoint in get_app().view_functions.values():
            spec.path(view=endpoint, app=get_app())

        # Set up global tags
        spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.SafeLoader)
        for path_value in spec_yaml["paths"].values():
            for data_value in path_value.values():
                if 'tags' in data_value and any(data_value['tags']):
                    for tag in data_value['tags']:
                        tags.add(tag)
        for tag in sorted(tags):
            spec.tag({'name': tag})

        if return_tags:
            return sorted(tags)

        if modify_default:
            file_path = Path(__file__).parent.parent.parent / 'openapi' / 'faraday_swagger.json'
        else:
            file_path = LOCAL_OPENAPI_FILE
            if not LOCAL_OPENAPI_FILE.parent.exists():
                LOCAL_OPENAPI_FILE.parent.mkdir()

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(json.dumps(spec.to_dict(), indent=4))


def show_all_urls():
    print(get_app().url_map)
