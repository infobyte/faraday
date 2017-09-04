import flask
import json

from flask_classful import FlaskView
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.routing import parse_rule
from server.models import Workspace


def output_json(data, code, headers=None):
    content_type = 'application/json'
    dumped = json.dumps(data)
    if headers:
        headers.update({'Content-Type': content_type})
    else:
        headers = {'Content-Type': content_type}
    response = flask.make_response(dumped, code, headers)
    return response


# TODO: Require @view decorator to enable custom routes
class GenericWorkspacedView(FlaskView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL"""

    # Must-implement attributes
    model_class = None
    schema_class = None

    # Default attributes
    route_prefix = '/v2/<workspace_name>/'
    base_args = ['workspace_name']  # Required to prevent double usage of <workspace_name>
    representations = {'application/json': output_json}
    lookup_field = 'id'

    @classmethod
    def get_route_base(cls):
        """Fix issue with base_args overriding

        See https://github.com/teracyhq/flask-classful/issues/50 for
        more information"""

        if cls.route_base is not None:
            route_base = cls.route_base
            base_rule = parse_rule(route_base)
            cls.base_args += [r[2] for r in base_rule]
        else:
            route_base = cls.default_route_base()

        return route_base.strip("/")

    def _get_schema_class(self):
        assert self.schema_class is not None, "You must define schema_class"
        return self.schema_class

    def _get_lookup_field(self):
        return getattr(self.model_class, self.lookup_field)

    def _get_workspace(self, workspace_name):
        try:
            ws = Workspace.query.filter_by(name=workspace_name).one()
        except NoResultFound:
            flask.abort(404, "No such workspace: %s" % workspace_name)
        return ws

    def _get_base_query(self, workspace_name):
        return self.model_class.query.join(Workspace) \
            .filter(Workspace.id==self._get_workspace(workspace_name).id)

    def _get_object(self, workspace_name, object_id):
        try:
            obj = self._get_base_query(workspace_name).filter(
                self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _dump(self, obj, **kwargs):
        return self._get_schema_class()(**kwargs).dump(obj)


class ListWorkspacedMixin(object):
    """Add GET /<workspace_name>/ route"""

    def index(self, workspace_name):
        return self._dump(self._get_base_query(workspace_name).all(),
                          many=True)


class RetrieveWorkspacedMixin(object):
    """Add GET /<workspace_name>/<id>/ route"""

    def get(self, workspace_name, object_id):
        return self._dump(self._get_object(workspace_name, object_id))


class ReadOnlyWorkspacedView(GenericWorkspacedView,
                             ListWorkspacedMixin,
                             RetrieveWorkspacedMixin):
    """A generic view with list and retrieve endpoints"""
    pass
