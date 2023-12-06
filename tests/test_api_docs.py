import json

import pytest
import yaml
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from apispec_webframeworks.flask import FlaskPlugin
from flask import current_app

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

        exc = {'/login', '/logout', '/change', '/reset', '/reset/{token}', '/verify', '/'}
        failing = []

        with current_app.test_request_context():
            for endpoint in current_app.view_functions:
                if endpoint in ('static', 'index'):
                    continue
                spec.path(view=current_app.view_functions[endpoint], app=current_app)

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

        with current_app.test_request_context():
            for endpoint in current_app.view_functions:
                if endpoint in ('static', 'index'):
                    continue
                spec.path(view=current_app.view_functions[endpoint], app=current_app)

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

        with current_app.test_request_context():
            for endpoint in current_app.view_functions:
                spec.path(view=current_app.view_functions[endpoint], app=current_app)

        spec_yaml = yaml.load(spec.to_yaml(), Loader=yaml.BaseLoader)

        for path_value in spec_yaml["paths"].values():
            for data_value in path_value.values():
                if 'tags' in data_value and any(data_value['tags']):
                    for tag in data_value['tags']:
                        tags.add(tag)

        assert sorted(tags) == openapi_format(return_tags=True)


@pytest.mark.usefixtures('logged_user')
class TestSwaggerApi:

    def test_get_swagger_json(self, test_client):
        response = test_client.get('/v3/swagger')
        assert response.status_code == 200
        assert response.content_type == 'application/json'
