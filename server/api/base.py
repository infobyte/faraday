'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import json

import flask
import sqlalchemy
from flask import g
from flask_classful import FlaskView
from sqlalchemy.orm import joinedload, undefer
from sqlalchemy.orm.exc import NoResultFound, ObjectDeletedError
from sqlalchemy.inspection import inspect
from sqlalchemy import func
from marshmallow import Schema
from marshmallow.compat import with_metaclass
from marshmallow.validate import Length
from marshmallow_sqlalchemy import ModelConverter
from marshmallow_sqlalchemy.schema import ModelSchemaMeta, ModelSchemaOpts
from webargs.flaskparser import FlaskParser, parser
from webargs.core import ValidationError
from faraday.server.models import Workspace, db, Command, CommandObject
from faraday.server.schemas import NullToBlankString
import faraday.server.utils.logger
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation
    )

logger = faraday.server.utils.logger.get_logger(__name__)


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
    """Abstract class to provide generic views. Inspired in `Django REST
    Framework generic viewsets`_.

    To create new views, you should create a class inheriting from
    GenericView (or from one of its subclasses) and set the model_class,
    schema_class, and optionally the rest of class attributes.

    Then, you should register it with your app by using the ``register``
    classmethod.

    .. _Django REST Framework generic viewsets: http://www.django-rest-framework.org/api-guide/viewsets/#genericviewset
    """

    # Must-implement attributes

    #: **Required**. The class of the SQLAlchemy model this view will handle
    model_class = None

    #: **Required** (unless _get_schema_class is overwritten).
    #: A subclass of `marshmallow.Schema` to serialize and deserialize the
    #: data provided by the user
    schema_class = None

    # Default attributes

    #: The prefix where the endpoint should be registered.
    #: This is useful for API versioning
    route_prefix = '/v2/'

    #: Arguments that are passed to the view but shouldn't change the route
    #: rule. This should be used when route_prefix is parametrized
    #:
    #: You tipically won't need this, unless you're creating nested views.
    #: For example GenericWorkspacedView use this so the workspace name is
    #: prepended to the view URL
    base_args = []

    #: Decides how you want to format the output response. It is set to dump a
    #: JSON object by default.
    #: See http://flask-classful.teracy.org/#adding-resource-representations-get-real-classy-and-put-on-a-top-hat
    #: for more information
    representations = {
        'application/json': output_json,
        'flask-classful/default': output_json,
    }

    ""
    #: Name of the field of the model used to get the object instance in
    #: retrieve, update and delete endpoints.
    #:
    #: For example, if you have a `Tag` model, maybe a `slug` would be good
    #: lookup field.
    #:
    #: .. note::
    #:     You must use a unique field here instead of one allowing
    #:     duplicate values
    #:
    #: .. note::
    #:     By default the lookup field value must be a valid integer. If you
    #:     want to allow any string, like with the slug field, make sure that
    #:     you set lookup_field_type to `string`
    lookup_field = 'id'

    #: A function that converts the string paremeter passed in the URL to the
    #: value that will be queried in the database.
    #: It defaults to int to match the type of the default lookup_field_type
    #: (id)
    lookup_field_type = int

    # Attributes to improve the performance of list and retrieve views

    #: List of relationships to eagerload in list and retrieve views.
    #:
    #: This is useful when you when you want to retrieve all childrens
    #: of an object in an API response, like for example if you want
    #: to have all hostnames of each host in the hosts endpoint.
    get_joinedloads = []  # List of relationships to eagerload

    #: List of columns that will be loaded directly when performing an
    #: eagerloaded query.
    #:
    #: This is useful when you have a column that is typically deferred because
    #: typically is isn't used, like the vuln creator. If you know you will use
    #: it, indicate it here to prevent doing an extra SQL query.
    get_undefer = []  # List of columns to undefer

    def _get_schema_class(self):
        """By default, it returns ``self.schema_class``.

        You can override it to define a custom behavior to be used
        in all views.
        """
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
        """Get a Field instance based on ``self.model_class`` and
        ``self.lookup_field``
        """
        return getattr(self.model_class, self.lookup_field)

    def _validate_object_id(self, object_id):
        """
        By default, it validates the value of the lookup field set by the user
        in the URL by calling ``self.lookup_field_type(object_id)``.
        If that raises a ValueError, que view will fail with error
        code 404.
        """
        try:
            self.lookup_field_type(object_id)
        except ValueError:
            flask.abort(404, 'Invalid format of lookup field')

    def _get_base_query(self):
        """Return the initial query all views should use

        .. warning::
            When you are creating views, avoid making SQL queries that
            don't inherit from this base query. You could easily forget
            to add workspace permission checks and similar stuff.
        """
        query = self.model_class.query
        return query

    def _get_eagerloaded_query(self, *args, **kwargs):
        """Load objects related to the current model in a single query.

        This is useful to prevent n+1 SQL problems, where a request to an
        object with many childs makes many SQL requests that tends to be
        slow.

        You tipically won't need to overwrite this method, but to set
        get_joinedloads and get_undefer attributes that are used by
        this method.

        In really complex cases where good performance is required,
        like in the vulns API endpoint, you will have to overwrite this.
        """
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
        """Return a new SQLAlchemy query with some filters applied.

        By default it doesn't do anything. It is overriden by
        :class:`FilterAlchemyMixin` to give support to Filteralchemy
        filters.

        .. warning::
            This is only used by the list endpoints. Don't use this
            to restrict the user the access for certain elements (like
            for example to restrict the items to one workspace). For
            this you must override _get_base_query instead.

            Always think that this filtering is optional, just a
            feature for the user to only see items he/she is interested
            in, so it is the user who will filter the data, not you

        """
        return query

    def _get_object(self, object_id, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
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
        """Serializes an object with the Marshmallow schema class
        returned by ``self._get_schema_class()``. Any passed kwargs
        will be passed to the ``__init__`` method of the schema.

        TODO migration: document route_kwargs
        """
        try:
            return self._get_schema_instance(route_kwargs, **kwargs).dump(obj).data
        except ObjectDeletedError:
            return []

    def _parse_data(self, schema, request, *args, **kwargs):
        """Deserializes from a Flask request to a dict with valid
        data. It a ``Marshmallow.Schema`` instance to perform the
        deserialization
        """
        return FlaskParser().parse(schema, request, locations=('json',),
                                   *args, **kwargs)

    @classmethod
    def register(cls, app, *args, **kwargs):
        """Register and add JSON error handler. Use error code
        400 instead of 409"""
        super(GenericView, cls).register(app, *args, **kwargs)

        @app.errorhandler(422)
        def handle_conflict(err):
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

        @app.errorhandler(409)
        def handle_conflict(err):
            # webargs attaches additional metadata to the `data` attribute
            exc = getattr(err, 'exc', None) or getattr(err, 'description', None)
            if exc:
                # Get validations from the ValidationError object
                messages = exc.messages
            else:
                messages = ['Invalid request']
            return flask.jsonify(messages), 409

        @app.errorhandler(InvalidUsage)
        def handle_invalid_usage(error):
            response = flask.jsonify(error.to_dict())
            response.status_code = error.status_code
            return response


class GenericWorkspacedView(GenericView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL

    .. note::
        This view inherits from GenericView, so make sure you understand
        that first by checking the docs above, or just by looking at the
        source code of server/api/base.py.

    """

    # Default attributes
    route_prefix = '/v2/ws/<workspace_name>/'
    base_args = ['workspace_name']  # Required to prevent double usage of <workspace_name>

    def _get_workspace(self, workspace_name):
        try:
            ws = Workspace.query.filter_by(name=workspace_name).one()
            if not ws.active:
                flask.abort(403, "Disabled workspace: %s" % workspace_name)
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

    def before_request(self, name, *args, **kwargs):
        sup = super(GenericWorkspacedView, self)
        if hasattr(sup, 'before_request'):
            sup.before_request(name, *args, **kwargs)
        if (self._get_workspace(kwargs['workspace_name']).readonly and
                flask.request.method not in ['GET', 'HEAD', 'OPTIONS']):
            flask.abort(403, "Altering a readonly workspace is not allowed")


class ListMixin(object):
    """Add GET / route"""

    #: If set (to a SQLAlchemy attribute instance) use this field to order the
    #: query by default
    order_field = None

    def _envelope_list(self, objects, pagination_metadata=None):
        """Override this method to define how a list of objects is
        rendered.

        See the example of :ref:`envelope-list-example` to learn
        when and how it should be used.
        """
        return objects

    def _paginate(self, query):
        """Overwrite this to implement pagination in the list endpoint.

        This is typically overwritten by SortableMixin.

        The method takes a query as argument and should return a tuple
        containing a new filtered query and a "pagination metadata"
        object that will be used by _envelope_list. If you don't need
        the latter just set is as None.
        """
        return query, None

    def _get_order_field(self, **kwargs):
        """Return the field used to sort the query.

        By default it returns the value of self.order_field, but it
        can be overwritten to something else, as SortableMixin does.
        """
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
    """Enables custom sorting by a field specified by the user

    See the example of :ref:`pagination-and-sorting-recipe` to learn
    how is it used.

    Works for both workspaced and non-workspaced views.
    """
    sort_field_paremeter_name = "sort"
    sort_direction_paremeter_name = "sort_dir"
    sort_pass_silently = False
    default_sort_direction = "asc"
    sort_model_class = None  # Override to use a model with more fields

    def _get_order_field(self, **kwargs):
        try:
            order_field = flask.request.args[self.sort_field_paremeter_name]
        except KeyError:
            # Sort field not specified, return the default
            return self.order_field
        # Check that the field is in the schema to prevent unwanted fields
        # value leaking
        schema = self._get_schema_instance(kwargs)

        # Add metadata nested field
        try:
            metadata_field = schema.fields.pop('metadata')
        except KeyError:
            pass
        else:
            for (key, value) in metadata_field.target_schema.fields.items():
                schema.fields['metadata.' + key] = value
                schema.fields[key] = value

        try:
            field_instance = schema.fields[order_field]
        except KeyError:
            if self.sort_pass_silently:
                logger.warn("Unknown field: %s" % order_field)
                return self.order_field
            raise InvalidUsage("Unknown field: %s" % order_field)

        # Translate from the field name in the schema to the database field
        # name
        order_field = field_instance.attribute or order_field

        # TODO migration: improve this checking or use a whitelist.
        # Handle PrimaryKeyRelatedField
        model_class = self.sort_model_class or self.model_class
        if order_field not in inspect(model_class).attrs:
            if self.sort_pass_silently:
                logger.warn("Field not in the DB: %s" % order_field)
                return self.order_field
            # It could be something like fields.Method
            raise InvalidUsage("Field not in the DB: %s" % order_field)

        if hasattr(model_class, order_field + '_id'):
            # Ugly hack to allow sorting by a parent
            field = getattr(model_class, order_field + '_id')
        else:
            field = getattr(model_class, order_field)
        sort_dir = flask.request.args.get(self.sort_direction_paremeter_name,
                                          self.default_sort_direction)
        if sort_dir not in ('asc', 'desc'):
            if self.sort_pass_silently:
                logger.warn("Invalid value for sorting direction: %s" %
                            sort_dir)
                return self.order_field
            raise InvalidUsage("Invalid value for sorting direction: %s" %
                               sort_dir)
        try:
            return getattr(field, sort_dir)()
        except NotImplementedError:
            if self.sort_pass_silently:
                logger.warn("field {} doesn't support sorting".format(
                    order_field
                ))
                return self.order_field
            # There are some fields that can't be used for sorting
            raise InvalidUsage("field {} doesn't support sorting".format(
                order_field
            ))


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
    """Add GET /<workspace_name>/<route_base>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    pass


class RetrieveMixin(object):
    """Add GET /<id>/ route"""

    def get(self, object_id, **kwargs):
        return self._dump(self._get_object(object_id, eagerload=True,
                                           **kwargs), kwargs)


class RetrieveWorkspacedMixin(RetrieveMixin):
    """Add GET /<workspace_name>/<route_base>/<id>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    pass


class ReadOnlyView(SortableMixin,
                   ListMixin,
                   RetrieveMixin,
                   GenericView):
    """A generic view with list and retrieve endpoints

    It is just a GenericView inheriting also from ListMixin,
    RetrieveMixin and SortableMixin.
    """
    pass


class ReadOnlyWorkspacedView(SortableMixin,
                             ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A workspaced generic view with list and retrieve endpoints

    It is just a GenericWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveWorkspacedMixin and SortableMixin"""
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
        """Check for conflicts and create a new object

        Is is passed the data parsed by the marshmallow schema (it
        transform from raw post data to a JSON)
        """
        obj = self.model_class(**data)
        # assert not db.session.new
        try:
            db.session.add(obj)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            conflict_obj = get_conflict_object(db.session, obj, data)
            if conflict_obj:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj).data,
                    }
                ))
            else:
                raise
        return obj


class CommandMixin():
    """
        Created the command obj to log model activity after a command
        execution via the api (ex. from plugins)
        This will use GET parameter command_id.
        NOTE: GET parameters are also available in POST requests
    """

    def _set_command_id(self, obj, created):
        try:
            # validates the data type from user input.
            command_id = int(flask.request.args.get('command_id', None))
        except TypeError:
            command_id = None

        if command_id:
            command = db.session.query(Command).filter(Command.id==command_id, Command.workspace==obj.workspace).first()
            if command is None:
                raise InvalidUsage('Command not found.')
            # if the object is created and updated in the same command
            # the command object already exists
            # we skip the creation.
            object_type = obj.__class__.__table__.name

            command_object = CommandObject.query.filter_by(
                object_id=obj.id,
                object_type=object_type,
                command=command,
                workspace=obj.workspace,
            ).first()
            if created or not command_object:
                command_object = CommandObject(
                    object_id=obj.id,
                    object_type=object_type,
                    command=command,
                    workspace=obj.workspace,
                    created_persistent=created
                )

            db.session.add(command)
            db.session.add(command_object)


class CreateWorkspacedMixin(CreateMixin, CommandMixin):
    """Add POST /<workspace_name>/<route_base>/ route

    If a GET parameter command_id is passed, it will create a new
    CommandObject associated to that command to register the change in
    the database.
    """

    def _perform_create(self, data, workspace_name):
        assert not db.session.new
        workspace = self._get_workspace(workspace_name)
        obj = self.model_class(**data)
        obj.workspace = workspace
        # assert not db.session.new
        try:
            db.session.add(obj)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = self._get_workspace(workspace_name)
            conflict_obj = get_conflict_object(db.session, obj, data, workspace)
            if conflict_obj:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj).data,
                    }
                ))
            else:
                raise

        self._set_command_id(obj, True)
        return obj


class UpdateMixin(object):
    """Add PUT /<id>/ route"""

    def put(self, object_id, **kwargs):
        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        # just in case an schema allows id as writable.
        data.pop('id', None)
        self._update_object(obj, data)
        self._perform_update(object_id, obj, data, **kwargs)

        return self._dump(obj, kwargs), 200

    def _update_object(self, obj, data):
        """Perform changes in the selected object

        It modifies the attributes of the SQLAlchemy model to match
        the data passed by the Marshmallow schema.

        It is common to overwrite this method to do something strange
        with some specific field. Typically the new method should call
        this one to handle the update of the rest of the fields.
        """
        for (key, value) in data.items():
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj, data, workspace_name=None):
        """Commit the SQLAlchemy session, check for updating conflicts"""
        try:
            db.session.add(obj)
            db.session.commit()
        except sqlalchemy.exc.IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = None
            if workspace_name:
                workspace = db.session.query(Workspace).filter_by(name=workspace_name).first()
            conflict_obj = get_conflict_object(db.session, obj, data, workspace)
            if conflict_obj:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj).data,
                    }
                ))
            else:
                raise
        return obj


class UpdateWorkspacedMixin(UpdateMixin, CommandMixin):
    """Add PUT /<workspace_name>/<route_base>/<id>/ route

    If a GET parameter command_id is passed, it will create a new
    CommandObject associated to that command to register the change in
    the database.
    """

    def _perform_update(self, object_id, obj, data, workspace_name=None):
        # # Make sure that if I created new objects, I had properly commited them
        # assert not db.session.new

        with db.session.no_autoflush:
            obj.workspace = self._get_workspace(workspace_name)

        self._set_command_id(obj, False)
        return super(UpdateWorkspacedMixin, self)._perform_update(
            object_id, obj, data, workspace_name)


class DeleteMixin(object):
    """Add DELETE /<id>/ route"""
    def delete(self, object_id, **kwargs):
        obj = self._get_object(object_id, **kwargs)
        self._perform_delete(obj, **kwargs)
        return None, 204

    def _perform_delete(self, obj, workspace_name=None):
        db.session.delete(obj)
        db.session.commit()


class DeleteWorkspacedMixin(DeleteMixin):
    """Add DELETE /<workspace_name>/<route_base>/<id>/ route"""

    def _perform_delete(self, obj, workspace_name=None):
        with db.session.no_autoflush:
            obj.workspace = self._get_workspace(workspace_name)

        return super(DeleteWorkspacedMixin, self)._perform_delete(
            obj, workspace_name)


class CountWorkspacedMixin(object):
    """Add GET /<workspace_name>/<route_base>/count/ route

    Group objects by the field set in the group_by GET parameter. If it
    isn't specified, the view will return a 404 error. For each group,
    show the count of elements and its value.

    This view is often used by some parts of the web UI. It was designed
    to keep backwards compatibility with the count endpoint of Faraday
    v2.
    """

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
            flask.abort(404)

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
    """A generic view with list, retrieve and create endpoints

    It is just a GenericView inheriting also from ListMixin,
    RetrieveMixin, SortableMixin, CreateMixin, UpdateMixin and
    DeleteMixin.
    """
    pass


class ReadWriteWorkspacedView(CreateWorkspacedMixin,
                              UpdateWorkspacedMixin,
                              DeleteWorkspacedMixin,
                              CountWorkspacedMixin,
                              ReadOnlyWorkspacedView):
    """A generic workspaced view with list, retrieve and create
    endpoints

    It is just a GenericWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveWorkspacedMixin, SortableMixin,
    CreateWorkspacedMixin, DeleteWorkspacedMixin and
    CountWorkspacedMixin.
    """
    pass


class CustomModelConverter(ModelConverter):
    """
    Model converter that automatically sets minimum length
    validators to not blankable fields
    """
    def _add_column_kwargs(self, kwargs, column):
        super(CustomModelConverter, self)._add_column_kwargs(kwargs, column)
        if not column.info.get('allow_blank', True):
            kwargs['validate'].append(Length(min=1))


class CustomModelSchemaOpts(ModelSchemaOpts):
    def __init__(self, *args, **kwargs):
        super(CustomModelSchemaOpts, self).__init__(*args, **kwargs)
        self.model_converter = CustomModelConverter


class AutoSchema(with_metaclass(ModelSchemaMeta, Schema)):
    """
    A Marshmallow schema that does field introspection based on
    the SQLAlchemy model specified in Meta.model.
    Unlike the marshmallow_sqlalchemy ModelSchema, it doesn't change
    the serialization and deserialization proccess.
    """
    OPTIONS_CLASS = CustomModelSchemaOpts

    # Use NullToBlankString instead of fields.String by default on text fields
    TYPE_MAPPING = Schema.TYPE_MAPPING.copy()
    TYPE_MAPPING[str] = NullToBlankString


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
