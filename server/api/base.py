import json

import flask
from flask import abort, g
from flask_classful import FlaskView
from sqlalchemy.orm import joinedload, undefer
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.inspection import inspect
from sqlalchemy import func
from marshmallow import Schema
from marshmallow.compat import with_metaclass
from marshmallow_sqlalchemy import ModelConverter
from marshmallow_sqlalchemy.schema import ModelSchemaMeta, ModelSchemaOpts
from webargs.flaskparser import FlaskParser, parser, abort
from webargs.core import ValidationError
from server.models import Workspace, db
import server.utils.logger

logger = server.utils.logger.get_logger(__name__)


def output_json(data, code, headers=None):
    content_type = 'application/json'
    dumped = json.dumps(data)
    if headers:
        headers.update({'Content-Type': content_type})
    else:
        headers = {'Content-Type': content_type}
    response = flask.make_response(dumped, code, headers)
    return response


class InvalidUsage(Exception):
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


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
    representations = {
        'application/json': output_json,
        'flask-classful/default': output_json,
    }
    lookup_field = 'id'
    lookup_field_type = int
    unique_fields = []  # Fields unique

    # Attributes to improve the performance of list and retrieve views
    get_joinedloads = []  # List of relationships to eagerload
    get_undefer = []  # List of columns to undefer

    def _get_schema_class(self):
        assert self.schema_class is not None, "You must define schema_class"
        return self.schema_class

    def _get_schema_instance(self, route_kwargs, **kwargs):
        """Instances a model schema.

        By default it uses sets strict to True
        but this can be overriden as well as any other parameters in
        the function's kwargs.

        It also uses _set_schema_context to set the context of the
        schema.
        """
        if 'strict' not in kwargs:
            kwargs['strict'] = True
        kwargs['context'] = self._set_schema_context(
            kwargs.get('context', {}), **route_kwargs)
        return self._get_schema_class()(**kwargs)

    def _set_schema_context(self, context, **kwargs):
        """This function can be overriden to update the context passed
        to the schema.
        """
        return context

    def _get_lookup_field(self):
        return getattr(self.model_class, self.lookup_field)

    def _validate_object_id(self, object_id):
        try:
            self.lookup_field_type(object_id)
        except ValueError:
            flask.abort(404, 'Invalid format of lookup field')

    def _get_base_query(self):
        query = self.model_class.query
        return query

    def _get_eagerloaded_query(self, *args, **kwargs):
        options = []
        try:
            has_creator = 'owner' in self._get_schema_class().opts.fields
        except AttributeError:
            has_creator = False
        if has_creator:
            # APIs for objects with metadata always return the creator's
            # username. Do a joinedload to prevent doing one query per object
            # (n+1) problem
            options.append(joinedload(
                getattr(self.model_class, 'creator')).load_only('username'))
        query = self._get_base_query(*args, **kwargs)
        options += [joinedload(relationship)
                    for relationship in self.get_joinedloads]
        options += [undefer(column) for column in self.get_undefer]
        return query.options(*options)

    def _filter_query(self, query):
        """Return a new SQLAlchemy query with some filters applied"""
        return query

    def _get_object(self, object_id, eagerload=False, **kwargs):
        self._validate_object_id(object_id)
        if eagerload:
            query = self._get_eagerloaded_query(**kwargs)
        else:
            query = self._get_base_query(**kwargs)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _dump(self, obj, route_kwargs, **kwargs):
        return self._get_schema_instance(route_kwargs, **kwargs).dump(obj).data

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

        @app.errorhandler(InvalidUsage)
        def handle_invalid_usage(error):
            response = flask.jsonify(error.to_dict())
            response.status_code = error.status_code
            return response


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
            Workspace.id == self._get_workspace(workspace_name).id)

    def _get_object(self, object_id, workspace_name, eagerload=False):
        self._validate_object_id(object_id)
        if eagerload:
            query = self._get_eagerloaded_query(workspace_name)
        else:
            query = self._get_base_query(workspace_name)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, 'Object with id "%s" not found' % object_id)
        return obj

    def _set_schema_context(self, context, **kwargs):
        """Overriden to pass the workspace name to the schema"""
        context.update(kwargs)
        return context

    def _validate_uniqueness(self, obj, object_id=None):
        # TODO: Use implementation of GenericView
        assert obj.workspace is not None, "Object must have a " \
            "workspace attribute set to call _validate_uniqueness"
        primary_key_field = inspect(self.model_class).primary_key[0]
        for field_name in self.unique_fields:
            field = getattr(self.model_class, field_name)
            value = getattr(obj, field_name)
            query = self._get_base_query(obj.workspace.name).filter(
                field == value)
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

    #: If set (to a SQLAlchemy attribute instance) use this field to order the
    #: query by default
    order_field = None

    def _envelope_list(self, objects, pagination_metadata=None):
        """Override this method to define how a list of objects is
        rendered"""
        return objects

    def _paginate(self, query):
        return query, None

    def _get_order_field(self, **kwargs):
        """Override this to enable custom sorting"""
        return self.order_field

    def index(self, **kwargs):
        query = self._filter_query(self._get_eagerloaded_query(**kwargs))
        order_field = self._get_order_field(**kwargs)
        if order_field is not None:
            query = query.order_by(order_field)
        objects, pagination_metadata = self._paginate(query)
        return self._envelope_list(self._dump(objects, kwargs, many=True),
                                   pagination_metadata)


class SortableMixin(object):
    """Enables custom sorting by a field specified by te user"""
    sort_field_paremeter_name = "sort"
    sort_direction_paremeter_name = "sort_dir"
    default_sort_direction = "asc"

    def _get_order_field(self, **kwargs):
        try:
            order_field = flask.request.args[self.sort_field_paremeter_name]
        except KeyError:
            # Sort field not specified, return the default
            return self.order_field
        # Check that the field is in the schema to prevent unwanted fields
        # value leaking
        schema = self._get_schema_instance(kwargs)
        try:
            field_instance = schema.fields[order_field]
        except KeyError:
            raise InvalidUsage("Unknown field: %s" % order_field)

        # Translate from the field name in the schema to the database field
        # name
        order_field = field_instance.attribute or order_field

        # TODO migration: improve this checking or use a whitelist.
        # Handle PrimaryKeyRelatedField
        if order_field not in inspect(self.model_class).attrs:
            # It could be something like fields.Method
            raise InvalidUsage("Field not in the DB: %s" % order_field)

        field = getattr(self.model_class, order_field)
        sort_dir = flask.request.args.get(self.sort_direction_paremeter_name,
                                          self.default_sort_direction)
        if sort_dir not in ('asc', 'desc'):
            raise InvalidUsage("Invalid value for sorting direction: %s" %
                               sort_dir)
        return getattr(field, sort_dir)()


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

            pagination_metadata = query.paginate(page=page, per_page=per_page, error_out=False)
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
        return self._dump(self._get_object(object_id, eagerload=True,
                                           **kwargs), kwargs)


class RetrieveWorkspacedMixin(RetrieveMixin):
    """Add GET /<workspace_name>/<id>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    pass


class ReadOnlyView(SortableMixin,
                   ListMixin,
                   RetrieveMixin,
                   GenericView):
    """A generic view with list and retrieve endpoints"""
    pass


class ReadOnlyWorkspacedView(SortableMixin,
                             ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A workspaced generic view with list and retrieve endpoints"""
    pass


class CreateMixin(object):
    """Add POST / route"""

    def post(self, **kwargs):
        context = {'updating': False}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        data.pop('id', None)
        created = self._perform_create(data, **kwargs)
        created.creator = g.user
        db.session.commit()
        return self._dump(created, kwargs), 201

    def _perform_create(self, data, **kwargs):
        obj = self.model_class(**data)
        # assert not db.session.new
        with db.session.no_autoflush:
            # Required because _validate_uniqueness does a select. Doing this
            # outside a no_autoflush block would result in a premature create.
            self._validate_uniqueness(obj)
            db.session.add(obj)
        return obj


class CreateWorkspacedMixin(CreateMixin):
    """Add POST /<workspace_name>/ route"""

    def _perform_create(self, data, workspace_name):
        assert not db.session.new
        workspace = self._get_workspace(workspace_name)
        obj = self.model_class(**data)
        obj.workspace = workspace
        # assert not db.session.new
        with db.session.no_autoflush:
            # Required because _validate_uniqueness does a select. Doing this
            # outside a no_autoflush block would result in a premature create.
            self._validate_uniqueness(obj)
            db.session.add(obj)
        db.session.commit()

        return obj


class UpdateMixin(object):
    """Add PUT /<workspace_name>/<id>/ route"""

    def put(self, object_id, **kwargs):
        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        # just in case an schema allows id as writable.
        data.pop('id', None)
        self._update_object(obj, data)
        updated = self._perform_update(object_id, obj, **kwargs)
        return self._dump(obj, kwargs), 200

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


class CountWorkspacedMixin(object):

    #: List of SQLAlchemy query filters to apply when counting
    count_extra_filters = []

    def count(self, **kwargs):
        res = {
            'groups': [],
            'total_count': 0
        }
        group_by = flask.request.args.get('group_by', None)
        # TODO migration: whitelist fields to avoid leaking a confidential
        # field's value.
        # Example: /users/count/?group_by=password
        # Also we should check that the field exists in the db and isn't, for
        # example, a relationship
        if not group_by or group_by not in inspect(self.model_class).attrs:
            abort(404)

        workspace_name = kwargs.pop('workspace_name')
        # using format is not a great practice.
        # the user input is group_by, however it's filtered by column name.
        table_name = inspect(self.model_class).tables[0].name
        group_by = '{0}.{1}'.format(table_name, group_by)

        count = self._filter_query(
            db.session.query(self.model_class)
            .join(Workspace)
            .group_by(group_by)
            .filter(Workspace.name == workspace_name,
                    *self.count_extra_filters))
        for key, count in count.values(group_by, func.count(group_by)):
            res['groups'].append(
                {'count': count,
                 'name': key,
                 # To add compatibility with the web ui
                 flask.request.args.get('group_by'): key,
                 }
            )
            res['total_count'] += count
        return res


class ReadWriteView(CreateMixin,
                    UpdateMixin,
                    DeleteMixin,
                    ReadOnlyView):
    """A generic view with list, retrieve and create endpoints"""
    pass


class ReadWriteWorkspacedView(CreateWorkspacedMixin,
                              UpdateWorkspacedMixin,
                              DeleteWorkspacedMixin,
                              CountWorkspacedMixin,
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


class FilterAlchemyModelConverter(ModelConverter):
    """Use this to make all fields of a model not required.

    It is used to make filteralchemy support not nullable columns"""

    def _add_column_kwargs(self, kwargs, column):
        super(FilterAlchemyModelConverter, self)._add_column_kwargs(kwargs,
                                                                    column)
        kwargs['required'] = False


class FilterSetMeta:
    """Base Meta class of FilterSet objects"""
    parser = parser
    converter = FilterAlchemyModelConverter()
