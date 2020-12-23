import json

import pytest
import yaml
from apispec import APISpec
from faraday.server.web import app
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from faraday.utils.faraday_openapi_plugin import FaradayAPIPlugin


def test_yaml_docs_with_defaults_or_no_docs():
    extra_specs = {
        'info': {'description': 'TEST'},
        'security': {"ApiKeyAuth": []},
        'servers': [{'url': 'https://localhost/_api'}]
    }

    spec = APISpec(
        title="Faraday API",
        version="2",
        openapi_version="3.0.2",
        plugins=[FaradayAPIPlugin(), FlaskPlugin(), MarshmallowPlugin()],
        **extra_specs
    )

    failing = []

    with app.test_request_context():
        for endpoint in app.view_functions:
            spec.path(view=app.view_functions[endpoint], app=app)
            spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.BaseLoader)

        for path_key, path_value in spec_yaml["paths"].items():

            path_temp = {path_key: {}}

            if not any(path_value):
                path_temp[path_key] = path_value
                failing.append(path_temp)
                continue
            else:
                for data_key, data_value in path_value.items():
                    if not any(data_value):
                        path_temp[path_key][data_key] = data_value

            if any(path_temp[path_key]):
                failing.append(path_temp)

    print(json.dumps(failing, indent=1))
    assert not any(failing)
