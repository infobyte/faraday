"""Flask plugin. Includes a path helper that allows you to pass a view
function to `path`. Inspects URL rules and view docstrings.

Passing a view function::

    from flask import Flask

    app = Flask(__name__)

    @app.route('/gists/<gist_id>')
    def gist_detail(gist_id):
        '''Gist detail view.
        ---
        x-extension: metadata
        get:
            responses:
                200:
                    schema:
                        $ref: '#/definitions/Gist'
        '''
        return 'detail for gist {}'.format(gist_id)

    with app.test_request_context():
        spec.path(view=gist_detail)
    print(spec.to_dict()['paths'])
    # {'/gists/{gist_id}': {'get': {'responses': {200: {'schema': {'$ref': '#/definitions/Gist'}}}},
    #                  'x-extension': 'metadata'}}

Passing a method view function::

    from flask import Flask
    from flask.views import MethodView

    app = Flask(__name__)

    class GistApi(MethodView):
        '''Gist API.
        ---
        x-extension: metadata
        '''
        def get(self):
           '''Gist view
           ---
           responses:
               200:
                   schema:
                       $ref: '#/definitions/Gist'
           '''
           pass

        def post(self):
           pass

    method_view = GistApi.as_view('gists')
    app.add_url_rule("/gists", view_func=method_view)
    with app.test_request_context():
        spec.path(view=method_view)

    # Alternatively, pass in an app object as a kwarg
    # spec.path(view=method_view, app=app)

    print(spec.to_dict()['paths'])
    # {'/gists': {'get': {'responses': {200: {'schema': {'$ref': '#/definitions/Gist'}}}},
    #             'post': {},
    #             'x-extension': 'metadata'}}


"""
# Standard library imports
import os
import re
import logging

# Related third party imports
from apispec import BasePlugin, yaml_utils
from apispec.exceptions import APISpecError
from flask import current_app
from flask.views import MethodView

# Local application imports
from faraday.server.api.base import GenericView

RE_URL = re.compile(r"<(?:[^:<>]+:)?([^<>]+)>")

logger = logging.getLogger(__name__)


class FaradayAPIPlugin(BasePlugin):
    """APISpec plugin for Flask"""

    @staticmethod
    def flaskpath2openapi(path):
        """Convert a Flask URL rule to an OpenAPI-compliant path.

        :param str path: Flask path template.
        """
        return RE_URL.sub(r"{\1}", path)

    @staticmethod
    def _rule_for_view(view, app=None):
        if app is None:
            app = current_app

        view_funcs = app.view_functions
        endpoint = None
        for ept, view_func in view_funcs.items():
            if view_func == view:
                endpoint = ept
        if not endpoint:
            raise APISpecError(f"Could not find endpoint for view {view}")

        # WARNING: Assume 1 rule per view function for now
        rule = app.url_map._rules_by_endpoint[endpoint][0]
        return rule

    def path_helper(self, operations, *, view, app=None, **kwargs):
        """Path helper that allows passing a Flask view function."""
        rule = self._rule_for_view(view, app=app)
        if '.' not in view.__qualname__:
            return self.flaskpath2openapi(rule.rule)
        view_name = view.__qualname__.split('.')[1]
        if view.__closure__ is None:
            return self.flaskpath2openapi(rule.rule)
        view_instance = next(cl.cell_contents for cl in view.__closure__ if isinstance(cl.cell_contents, GenericView))
        if view_name in ['get', 'put', 'post', 'delete']:
            if view.__doc__:
                if hasattr(view_instance.model_class, "__name__"):
                    class_model = view_instance.model_class.__name__
                else:
                    class_model = 'No name'
                # print(f'{view_name} / {class_model}')
                logger.debug(f'{view_name} / {class_model} / {rule.methods} / {view_name} / '
                             f'{view_instance._get_schema_class().__name__}')
                operations[view_name] = yaml_utils.load_yaml_from_docstring(
                    view.__doc__.format(schema_class=view_instance._get_schema_class().__name__,
                                        class_model=class_model,
                                        tag_name=class_model,
                                        route_base=view_instance.route_base)
                )
        elif hasattr(view, "__doc__"):
            if not view.__doc__:
                view.__doc__ = ""
            if hasattr(view_instance.model_class, "__name__"):
                class_model = view_instance.model_class.__name__
            else:
                class_model = 'No name'
            for method in rule.methods:
                logger.debug(f'{view_name} / {class_model} / {rule.methods} / {method} / '
                             f'{view_instance._get_schema_class().__name__}')
                if method not in ['HEAD', 'OPTIONS'] or os.environ.get("FULL_API_DOC", None):
                    operations[method.lower()] = yaml_utils.load_yaml_from_docstring(
                        view.__doc__.format(schema_class=view_instance._get_schema_class().__name__,
                                            class_model=class_model,
                                            tag_name=class_model,
                                            route_base=view_instance.route_base)
                    )
        if hasattr(view, "view_class") and issubclass(view.view_class, MethodView):
            for method in view.methods:
                if method in rule.methods:
                    method_name = method.lower()
                    method = getattr(view.view_class, method_name)
                    operations[method_name] = yaml_utils.load_yaml_from_docstring(
                        method.__doc__
                    )

        return self.flaskpath2openapi(rule.rule)
