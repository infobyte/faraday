import flask
import json

from flask_classful import FlaskView
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.inspection import inspect
from werkzeug.routing import parse_rule
from webargs.flaskparser import FlaskParser, abort
from webargs.core import ValidationError
from server.models import Workspace, db


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
    unique_fields = []  # Fields unique together with workspace_id

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

    def _parse_data(self, schema, request, *args, **kwargs):
        return FlaskParser().parse(schema, request, locations=('json',),
                                   *args, **kwargs)

    def _validate_uniqueness(self, obj, object_id=None):
        assert obj.workspace is not None, "Object must have a " \
            "workspace attribute set to call _validate_uniqueness"
        primary_key_field = inspect(self.model_class).primary_key[0]
        for field_name in self.unique_fields:
            field = getattr(self.model_class, field_name)
            value = getattr(obj, field_name)
            query = self._get_base_query(obj.workspace.name).filter(
                field==value)
            if object_id is not None:
                # The object already exists in DB, we want to fetch an object
                # different to this one but with the same unique field
                query = query.filter(primary_key_field != object_id)
            if query.one_or_none():
                db.session.rollback()
                abort(422, ValidationError('Existing value for %s field: %s' % (
                    field_name, value
                )))

    @classmethod
    def register(cls, app, *args, **kwargs):
        """Register and add JSON error handler. Use error code
        400 instead of 422"""
        super(GenericWorkspacedView, cls).register(app, *args, **kwargs)
        @app.errorhandler(422)
        def handle_unprocessable_entity(err):
            # webargs attaches additional metadata to the `data` attribute
            exc = getattr(err, 'exc')
            if exc:
                # Get validations from the ValidationError object
                messages = exc.messages
            else:
                messages = ['Invalid request']
            return flask.jsonify({
                'messages': messages,
            }), 400

class ListWorkspacedMixin(object):
    """Add GET /<workspace_name>/ route"""

    def index(self, workspace_name):
        return self._dump(self._get_base_query(workspace_name).all(),
                          many=True)


class RetrieveWorkspacedMixin(object):
    """Add GET /<workspace_name>/<id>/ route"""

    def get(self, workspace_name, object_id):
        return self._dump(self._get_object(workspace_name, object_id))


class ReadOnlyWorkspacedView(ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A generic view with list and retrieve endpoints"""
    pass


class CreateWorkspacedMixin(object):

    def post(self, workspace_name):
        data = self._parse_data(self._get_schema_class()(strict=True),
                                flask.request)
        obj = self.model_class(**data)
        created = self._perform_create(workspace_name, obj)
        return self._dump(created).data, 201

    def _perform_create(self, workspace_name, obj):
        assert not db.session.new
        with db.session.no_autoflush:
            # Required because _validate_uniqueness does a select. Doing this
            # outside a no_autoflush block would result in a premature create.
            obj.workspace = self._get_workspace(workspace_name)
            self._validate_uniqueness(obj)
            db.session.add(obj)
        db.session.commit()
        return obj


class UpdateWorkspacedMixin(object):
    def put(self, workspace_name, object_id):
        data = self._parse_data(self._get_schema_class()(strict=True),
                                flask.request)
        obj = self._get_object(workspace_name, object_id)
        self._update_object(obj, data)
        updated = self._perform_update(workspace_name, object_id, obj)
        return self._dump(obj).data, 200

    def _update_object(self, obj, data):
        for (key, value) in data.items():
            setattr(obj, key, value)

    def _perform_update(self, workspace_name, object_id, obj):
        with db.session.no_autoflush:
            obj.workspace = self._get_workspace(workspace_name)
            self._validate_uniqueness(obj, object_id)
        db.session.add(obj)
        db.session.commit()


class DeleteWorkspacedMixin(object):
    def delete(self, workspace_name, object_id):
        obj = self._get_object(workspace_name, object_id)
        self._perform_delete(obj)
        return None, 204

    def _perform_delete(self, obj):
        db.session.delete(obj)
        db.session.commit()


class ReadWriteWorkspacedView(CreateWorkspacedMixin,
                              UpdateWorkspacedMixin,
                              DeleteWorkspacedMixin,
                              ReadOnlyWorkspacedView,
                              GenericWorkspacedView):
    """A generic view with list, retrieve and create endpoints"""
    pass
