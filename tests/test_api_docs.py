import json

import pytest
import yaml
from apispec import APISpec
from faraday.server.web import get_app
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from faraday.utils.faraday_openapi_plugin import FaradayAPIPlugin
from faraday.server.commands.app_urls import openapi_format

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


class TestDocs:

    def test_yaml_docs_with_no_doc(self):

        exc = {'/login', '/logout', '/change', '/reset', '/reset/{token}', '/verify'}
        failing = []

        with get_app().test_request_context():
            for endpoint in get_app().view_functions:
                spec.path(view=get_app().view_functions[endpoint], app=get_app())

        spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.BaseLoader)

        for path_key, path_value in spec_yaml["paths"].items():

            if path_key in exc:
                continue

            path_temp = {path_key: {}}

            if not any(path_value):
                failing.append(path_temp)

        if any(failing):
            print("Endpoints with no docs\n")
            print(json.dumps(failing, indent=1))
        assert not any(failing)

    def test_yaml_docs_with_defaults(self):

        failing = []

        with get_app().test_request_context():
            for endpoint in get_app().view_functions:
                spec.path(view=get_app().view_functions[endpoint], app=get_app())

        spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.BaseLoader)

        for path_key, path_value in spec_yaml["paths"].items():

            path_temp = {path_key: {}}

            for data_key, data_value in path_value.items():
                if not any(data_value):
                    path_temp[path_key][data_key] = data_value

            if any(path_temp[path_key]):
                failing.append(path_temp)

        if any(failing):
            print("Endpoints with default docs:\n")
            print(json.dumps(failing, indent=1))
        assert not any(failing)

    @pytest.mark.skip(reason="Changed logic")
    def test_tags_sorted_correctly(self):

        tags = set()

        with get_app().test_request_context():
            for endpoint in get_app().view_functions:
                spec.path(view=get_app().view_functions[endpoint], app=get_app())

        spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.BaseLoader)

        for path_value in spec_yaml["paths"].values():
            for data_value in path_value.values():
                if 'tags' in data_value and any(data_value['tags']):
                    for tag in data_value['tags']:
                        tags.add(tag)

        assert sorted(tags) == openapi_format(return_tags=True)
