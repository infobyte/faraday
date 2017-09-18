import flask
import json

from flask_classful import FlaskView
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.inspection import inspect
from werkzeug.routing import parse_rule
from marshmallow import Schema
from marshmallow.compat import with_metaclass
from marshmallow_sqlalchemy.schema import ModelSchemaMeta, ModelSchemaOpts
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
class GenericView(FlaskView):
    """Abstract class to provide helpers. Inspired in Django REST
    Framework generic viewsets"""

    # Must-implement attributes
    model_class = None
    schema_class = None

    # Default attributes
    route_prefix = '/v2/'
    base_args = []
    representations = {'application/json': output_json}
    lookup_field = 'id'
    lookup_field_type = int
    unique_fields = []  # Fields unique

    def _get_schema_class(self):
        assert self.schema_class is not None, "You must define schema_class"
        return self.schema_class

    def _get_lookup_field(self):
        return getattr(self.model_class, self.lookup_field)

    def _validate_object_id(self, object_id):
        try:
            self.lookup_field_type(object_id)
        except ValueError:
            flask.abort(404, 'Invalid format of lookup field')

    def _get_base_query(self):
        return self.model_class.query

    def _get_object(self, object_id, **kwargs):
        self._validate_object_id(object_id)
        try:
            obj = self._get_base_query(**kwargs).filter(
                self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _dump(self, obj, **kwargs):
        return self._get_schema_class()(**kwargs).dump(obj).data

    def _parse_data(self, schema, request, *args, **kwargs):
        return FlaskParser().parse(schema, request, locations=('json',),
                                   *args, **kwargs)

    def _validate_uniqueness(self, obj, object_id=None):
        # TODO: Implement this
        return True

    @classmethod
    def register(cls, app, *args, **kwargs):
        """Register and add JSON error handler. Use error code
        400 instead of 422"""
        super(GenericView, cls).register(app, *args, **kwargs)
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


class GenericWorkspacedView(GenericView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL"""

    # Default attributes
    route_prefix = '/v2/ws/<workspace_name>/'
    base_args = ['workspace_name']  # Required to prevent double usage of <workspace_name>
    unique_fields = []  # Fields unique together with workspace_id

    def _get_workspace(self, workspace_name):
        try:
            ws = Workspace.query.filter_by(name=workspace_name).one()
        except NoResultFound:
            flask.abort(404, "No such workspace: %s" % workspace_name)
        return ws

    def _get_base_query(self, workspace_name):
        base = super(GenericWorkspacedView, self)._get_base_query()
        return base.join(Workspace).filter(
            Workspace.id==self._get_workspace(workspace_name).id)

    def _get_object(self, object_id, workspace_name):
        self._validate_object_id(object_id)
        try:
            obj = self._get_base_query(workspace_name).filter(
                self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _validate_uniqueness(self, obj, object_id=None):
        # TODO: Use implementation of GenericView
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


class ListMixin(object):
    """Add GET / route"""

    def _envelope_list(self, objects, pagination_metadata=None):
        """Override this method to define how a list of objects is
        rendered"""
        return objects

    def _paginate(self, query):
        return query, None

    def _filter_query(self, query):
        """Return a new SQLAlchemy query with some filters applied"""
        return query

    def index(self, **kwargs):
        query = self._filter_query(self._get_base_query(**kwargs))
        objects, pagination_metadata = self._paginate(query)
        return self._envelope_list(self._dump(objects, many=True),
                                   pagination_metadata)


class PaginatedMixin(object):
    """Add pagination for list route"""
    per_page_parameter_name = 'page_size'
    page_number_parameter_name = 'page'

    def _paginate(self, query):
        if self.per_page_parameter_name in flask.request.args:

            try:
                page = int(flask.request.args.get(
                    self.page_number_parameter_name, 1))
            except (TypeError, ValueError):
                flask.abort(404, 'Invalid page number')

            try:
                per_page = int(flask.request.args[
                    self.per_page_parameter_name])
            except (TypeError, ValueError):
                flask.abort(404, 'Invalid per_page value')

            pagination_metadata = query.paginate(page=page, per_page=per_page)
            return pagination_metadata.items, pagination_metadata
        return super(PaginatedMixin, self)._paginate(query)


class FilterAlchemyMixin(object):
    """Add querystring parameter filtering to list route

    It is done by setting the ViewClass.filterset_class class
    attribute
    """

    filterset_class = None

    def _filter_query(self, query):
        assert self.filterset_class is not None, 'You must define a filterset'
        return self.filterset_class(query).filter()


class ListWorkspacedMixin(ListMixin):
    """Add GET /<workspace_name>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    pass


class RetrieveMixin(object):
    """Add GET /<id>/ route"""

    def get(self, object_id, **kwargs):
        return self._dump(self._get_object(object_id, **kwargs))


class RetrieveWorkspacedMixin(RetrieveMixin):
    """Add GET /<workspace_name>/<id>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    pass


class ReadOnlyView(ListMixin,
                   RetrieveMixin,
                   GenericView):
    """A generic view with list and retrieve endpoints"""
    pass


class ReadOnlyWorkspacedView(ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A workspaced generic view with list and retrieve endpoints"""
    pass


class CreateMixin(object):
    """Add POST / route"""

    def post(self, **kwargs):
        data = self._parse_data(self._get_schema_class()(strict=True),
                                flask.request)
        obj = self.model_class(**data)
        created = self._perform_create(obj, **kwargs)
        return self._dump(created), 201

    def _perform_create(self, obj):
        # assert not db.session.new
        with db.session.no_autoflush:
            # Required because _validate_uniqueness does a select. Doing this
            # outside a no_autoflush block would result in a premature create.
            self._validate_uniqueness(obj)
            db.session.add(obj)
        db.session.commit()
        return obj


class CreateWorkspacedMixin(CreateMixin):
    """Add POST /<workspace_name>/ route"""

    def _perform_create(self, obj, workspace_name):
        assert not db.session.new
        obj.workspace = self._get_workspace(workspace_name)
        return super(CreateWorkspacedMixin, self)._perform_create(obj)


class UpdateMixin(object):
    """Add PUT /<workspace_name>/<id>/ route"""

    def put(self, object_id, **kwargs):
        data = self._parse_data(self._get_schema_class()(strict=True),
                                flask.request)
        obj = self._get_object(object_id, **kwargs)
        self._update_object(obj, data)
        updated = self._perform_update(object_id, obj, **kwargs)
        return self._dump(obj), 200

    def _update_object(self, obj, data):
        for (key, value) in data.items():
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj):
        with db.session.no_autoflush:
            self._validate_uniqueness(obj, object_id)
        db.session.add(obj)
        db.session.commit()


class UpdateWorkspacedMixin(UpdateMixin):
    """Add PUT /<id>/ route"""

    def _perform_update(self, object_id, obj, workspace_name):
        assert not db.session.new
        with db.session.no_autoflush:
            obj.workspace = self._get_workspace(workspace_name)
        return super(UpdateWorkspacedMixin, self)._perform_update(
            object_id, obj)


class DeleteMixin(object):
    """Add DELETE /<id>/ route"""
    def delete(self, object_id, **kwargs):
        obj = self._get_object(object_id, **kwargs)
        self._perform_delete(obj)
        return None, 204

    def _perform_delete(self, obj):
        db.session.delete(obj)
        db.session.commit()


class DeleteWorkspacedMixin(DeleteMixin):
    """Add DELETE /<workspace_name>/<id>/ route"""
    pass


class ReadWriteView(CreateMixin,
                    UpdateMixin,
                    DeleteMixin,
                    ReadOnlyView):
    """A generic view with list, retrieve and create endpoints"""
    pass


class ReadWriteWorkspacedView(CreateWorkspacedMixin,
                              UpdateWorkspacedMixin,
                              DeleteWorkspacedMixin,
                              ReadOnlyWorkspacedView):
    """A generic workspaced view with list, retrieve and create
    endpoints"""
    pass


class AutoSchema(with_metaclass(ModelSchemaMeta, Schema)):
    """
    A Marshmallow schema that does field introspection based on
    the SQLAlchemy model specified in Meta.model.
    Unlike the marshmallow_sqlalchemy ModelSchema, it doesn't change
    the serialization and deserialization proccess.
    """
    OPTIONS_CLASS = ModelSchemaOpts
