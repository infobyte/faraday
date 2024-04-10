"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging
import datetime
import json
from json import JSONDecodeError
from typing import Tuple, List, Dict
from collections import defaultdict
import time

# Related third party imports
import flask
import flask_login
import sqlalchemy
from sqlalchemy import func, desc, asc, and_
from sqlalchemy.orm import joinedload, undefer, with_expression
from sqlalchemy.orm.exc import NoResultFound, ObjectDeletedError
from sqlalchemy.inspection import inspect
from sqlalchemy.sql.elements import BooleanClauseList
from flask_classful import FlaskView, route
from marshmallow import Schema, EXCLUDE, fields
from marshmallow.validate import Length
from marshmallow_sqlalchemy import ModelConverter
from marshmallow_sqlalchemy.schema import SQLAlchemyAutoSchemaOpts, SQLAlchemyAutoSchemaMeta
from webargs.flaskparser import FlaskParser
from webargs.core import ValidationError

# Local application imports
from faraday.server.models import (
    Workspace,
    Command,
    CommandObject,
    WorkspacePermission,
    db,
    count_vulnerability_severities,
    _make_vuln_count_property,
    _make_generic_count_property,
)
from faraday.server.schemas import NullToBlankString
from faraday.server.utils.database import (
    get_conflict_object,
    is_unique_constraint_violation,
    not_null_constraint_violation,
)
from faraday.server.utils.filters import FlaskRestlessSchema
from faraday.server.utils.search import search
from faraday.server.config import faraday_server

logger = logging.getLogger(__name__)


def output_json(data, code, headers=None):
    content_type = 'application/json'
    dumped = json.dumps(data)
    if headers:
        headers.update({'Content-Type': content_type})
    else:
        headers = {'Content-Type': content_type}
    response = flask.make_response(dumped, code, headers)
    return response


def get_filtered_data(filters, filter_query):
    column_names = ['count'] + [field['field'] for field in filters.get('group_by', [])]
    rows = [list(zip(column_names, row)) for row in filter_query.all()]
    data = []
    for row in rows:
        data.append({field[0]: field[1] for field in row})

    return data, len(rows)


def get_group_by_and_sort_dir(model_class):
    group_by = flask.request.args.get('group_by', None)
    sort_dir = flask.request.args.get('order', "asc").lower()

    # TODO migration: whitelist fields to avoid leaking a confidential
    # field's value.
    # Example: /users/count/?group_by=password
    # Also we should check that the field exists in the db and isn't, for
    # example, a relationship
    if not group_by or group_by not in inspect(model_class).attrs:
        flask.abort(400, {"message": "group_by is a required parameter"})

    if sort_dir and sort_dir not in ('asc', 'desc'):
        flask.abort(400, {"message": "order must be 'desc' or 'asc'"})

    return group_by, sort_dir


def get_workspace(workspace_name):
    try:
        ws = Workspace.query.filter_by(name=workspace_name).one()
        if not ws.active:
            flask.abort(403, f"Disabled workspace: {workspace_name}")
        return ws
    except NoResultFound:
        flask.abort(404, f"No such workspace: {workspace_name}")


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

    .. _Django REST Framework generic viewsets: https://www.django-rest-framework.org/api-guide/viewsets/#genericviewset
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
    route_prefix = '/v3/'

    #: Arguments that are passed to the view but shouldn't change the route
    #: rule. This should be used when route_prefix is parametrized
    #:
    #: You typically won't need this, unless you're creating nested views.
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

    #: A function that converts the string parameter passed in the URL to the
    #: value that will be queried in the database.
    #: It defaults to int to match the type of the default lookup_field_type
    #: (id)
    lookup_field_type = int

    # Attributes to improve the performance of list and retrieve views

    #: List of relationships to eagerload in list and retrieve views.
    #:
    #: This is useful when you when you want to retrieve all children
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

    trailing_slash = False

    def _get_schema_class(self):
        """By default, it returns ``self.schema_class``.

        You can override it to define a custom behavior to be used
        in all views.
        """
        assert self.schema_class is not None, "You must define schema_class"
        return self.schema_class

    def _get_schema_instance(self, route_kwargs, **kwargs):
        """Instances a model schema.

        It also uses _set_schema_context to set the context of the
        schema.
        """
        kwargs['context'] = self._set_schema_context(
            kwargs.get('context', {}), **route_kwargs)

        # If the client send us fields that are not in the schema, ignore them
        # This is the default in marshmallow 2, but not in marshmallow 3
        kwargs['unknown'] = EXCLUDE

        return self._get_schema_class()(**kwargs)

    def _set_schema_context(self, context, **kwargs):
        """This function can be overridden to update the context passed
        to the schema.
        """
        return context

    def _get_lookup_field(self):
        """Get a Field instance based on ``self.model_class`` and
        ``self.lookup_field``
        """
        return getattr(self.model_class, self.lookup_field)

    def _validate_object_id(self, object_id, raise_error=True):
        """
        By default, it validates the value of the lookup field set by the user
        in the URL by calling ``self.lookup_field_type(object_id)``.
        If that raises a ValueError, que view will fail with error
        code 404.
        """
        try:
            self.lookup_field_type(object_id)
        except ValueError:
            if raise_error:
                flask.abort(404, 'Invalid format of lookup field')
            return False
        return True

    def _get_base_query(self, *args, **kwargs):
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

        You typically won't need to overwrite this method, but to set
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

        By default it doesn't do anything. It is overridden by
        :class:`FilterAlchemyMixin` to give support to FilterAlchemy
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

    def _get_object(self, object_id, workspace_name=None, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        obj = None
        self._validate_object_id(object_id)
        if eagerload:
            query = self._get_eagerloaded_query(**kwargs)
        else:
            query = self._get_base_query(**kwargs)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, f'Object with id "{object_id}" not found')
        return obj

    def _get_objects(self, object_ids, eagerload=False, **kwargs):
        """
        Given the object_id and extra route params, get an instance of
        ``self.model_class``
        """
        object_ids = [object_id for object_id in object_ids if self._validate_object_id(object_id, raise_error=False)]
        if eagerload:
            query = self._get_eagerloaded_query(**kwargs)
        else:
            query = self._get_base_query(**kwargs)
        try:
            obj = query.filter(self._get_lookup_field().in_(object_ids)).all()
        except NoResultFound:
            return []
        return obj

    def _dump(self, obj, route_kwargs, **kwargs):
        """Serializes an object with the Marshmallow schema class
        returned by ``self._get_schema_class()``. Any passed kwargs
        will be passed to the ``__init__`` method of the schema.

        TODO migration: document route_kwargs
        """
        try:
            return self._get_schema_instance(route_kwargs, **kwargs).dump(obj)
        except ObjectDeletedError:
            return []

    @staticmethod
    def _parse_data(schema, request, *args, **kwargs):
        """Deserializes from a Flask request to a dict with valid
        data. It a ``Marshmallow.Schema`` instance to perform the
        deserialization
        """
        return FlaskParser(unknown=EXCLUDE).parse(schema, request, location="json",
                                                  *args, **kwargs)

    @classmethod
    def register(cls, app, *args, **kwargs):
        """Register and add JSON error handler. Use error code
        400 instead of 409"""
        super().register(app, *args, **kwargs)

        @app.errorhandler(422)
        def handle_error(err):  # pylint: disable=unused-variable
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
        def handle_conflict(err):  # pylint: disable=unused-variable
            # webargs attaches additional metadata to the `data` attribute
            exc = getattr(err, 'exc', None) or getattr(err, 'description', None)
            if exc:
                # Get validations from the ValidationError object
                messages = exc.messages
            else:
                messages = ['Invalid request']
            return flask.jsonify(messages), 409

        @app.errorhandler(403)
        def handle_forbidden(err):  # pylint: disable=unused-variable
            return flask.jsonify({"message": err.description}), 403

        @app.errorhandler(InvalidUsage)
        def handle_invalid_usage(error):  # pylint: disable=unused-variable
            response = flask.jsonify(error.to_dict())
            response.status_code = error.status_code
            return response

        """# @app.errorhandler(404)
        def handle_not_found(err):  # pylint: disable=unused-variable
            response = {'success': False, 'message': err.description if faraday_server.debug else err.name}
            return flask.jsonify(response), 404"""

        @app.errorhandler(500)
        def handle_server_error(err):  # pylint: disable=unused-variable
            response = {'success': False,
                        'message': f"Exception: {err.original_exception}" if faraday_server.debug else
                        'Internal Server Error'}
            return flask.jsonify(response), 500


class GenericWorkspacedView(GenericView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL

    .. note::
        This view inherits from GenericView, so make sure you understand
        that first by checking the docs above, or just by looking at the
        source code of server/api/base.py.

    """

    # Default attributes
    route_prefix = '/v3/ws/<workspace_name>/'
    base_args = ['workspace_name']  # Required to prevent double usage of <workspace_name>

    def _get_base_query(self, workspace_name):
        base = super()._get_base_query()
        return base.join(Workspace).filter(
            Workspace.id == get_workspace(workspace_name).id)

    def _get_object(self, object_id, workspace_name=None, eagerload=False, **kwargs):
        self._validate_object_id(object_id)
        obj = None
        if eagerload:
            query = self._get_eagerloaded_query(workspace_name)
        else:
            query = self._get_base_query(workspace_name)
        try:
            obj = query.filter(self._get_lookup_field() == object_id).one()
        except NoResultFound:
            flask.abort(404, f'Object with id "{object_id}" not found')
        return obj

    def _set_schema_context(self, context, **kwargs):
        """Overridden to pass the workspace name to the schema"""
        context.update(kwargs)
        return context

    def before_request(self, name, *args, **kwargs):
        sup = super()
        if hasattr(sup, 'before_request'):
            sup.before_request(name, *args, **kwargs)
        if (get_workspace(kwargs['workspace_name']).readonly
                and flask.request.method not in ['GET', 'HEAD', 'OPTIONS']):
            flask.abort(403, "Altering a readonly workspace is not allowed")


class GenericMultiWorkspacedView(GenericWorkspacedView):
    """Abstract class for a view that depends on the workspace, that is
    passed in the URL. The object can be accessed from more than one workspace.

    .. note::
        This view inherits from GenericWorkspacedView and GenericView, so make
        sure you understand those first by checking the docs above, or just
        by looking at the source code of server/api/base.py.

    """

    def _get_base_query(self, workspace_name):
        base = super(GenericWorkspacedView, self)._get_base_query()
        return base.filter(
            self.model_class.workspaces.any(
                name=get_workspace(workspace_name).name
            )
        )


class ListMixin:
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

    @staticmethod
    def _paginate(query):
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
        """
          ---
          tags: [{tag_name}]
          summary: "Get a list of {class_model}."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        exclude = kwargs.pop('exclude', [])
        query = self._filter_query(self._get_eagerloaded_query(**kwargs))
        order_field = self._get_order_field(**kwargs)
        if order_field is not None:
            if isinstance(order_field, tuple):
                query = query.order_by(*order_field)
            else:
                query = query.order_by(order_field)
        objects, pagination_metadata = self._paginate(query)
        if not isinstance(objects, list):
            objects = objects.limit(None).offset(0)
        return self._envelope_list(self._dump(objects, kwargs, many=True, exclude=exclude),
                                   pagination_metadata)


class SortableMixin:
    """Enables custom sorting by a field specified by the user

    See the example of :ref:`pagination-and-sorting-recipe` to learn
    how is it used.

    Works for both workspaced and non-workspaced views.
    """
    sort_field_parameter_name = "sort"
    sort_direction_parameter_name = "sort_dir"
    sort_pass_silently = False
    default_sort_direction = "asc"
    sort_model_class = None  # Override to use a model with more fields

    def _get_order_field(self, **kwargs):
        try:
            order_field = flask.request.args[self.sort_field_parameter_name]
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
        except KeyError as e:
            if self.sort_pass_silently:
                logger.warning(f"Unknown field: {order_field}")
                return self.order_field
            raise InvalidUsage(f"Unknown field: {order_field}") from e
        # Translate from the field name in the schema to the database field
        # name
        order_field = field_instance.attribute or order_field

        # TODO migration: improve this checking or use a whitelist.
        # Handle PrimaryKeyRelatedField
        model_class = self.sort_model_class or self.model_class
        if order_field not in inspect(model_class).attrs:
            if self.sort_pass_silently:
                logger.warning(f"Field not in the DB: {order_field}")
                return self.order_field
            # It could be something like fields.Method
            raise InvalidUsage(f"Field not in the DB: {order_field}")

        if hasattr(model_class, order_field + '_id'):
            # Ugly hack to allow sorting by a parent
            field = getattr(model_class, order_field + '_id')
        else:
            field = getattr(model_class, order_field)
        sort_dir = flask.request.args.get(self.sort_direction_parameter_name,
                                          self.default_sort_direction)
        if sort_dir not in ('asc', 'desc'):
            if self.sort_pass_silently:
                logger.warning(f"Invalid value for sorting direction: {sort_dir}")
                return self.order_field
            raise InvalidUsage(f"Invalid value for sorting direction: {sort_dir}")
        try:
            if self.order_field is not None:
                if not isinstance(self.order_field, tuple):
                    self.order_field = (self.order_field,)
                return (getattr(field, sort_dir)(),) + self.order_field
            else:
                return getattr(field, sort_dir)()
        except NotImplementedError as e:
            if self.sort_pass_silently:
                logger.warning(f"field {order_field} doesn't support sorting")
                return self.order_field
            # There are some fields that can't be used for sorting
            raise InvalidUsage(f"field {order_field} doesn't support sorting") from e


class PaginatedMixin:
    """Add pagination for list route"""
    per_page_parameter_name = 'page_size'
    page_number_parameter_name = 'page'

    def _paginate(self, query):
        page, per_page = None, None
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
        return super()._paginate(query)


class FilterAlchemyMixin:
    """Add querystring parameter filtering to list route

    It is done by setting the ViewClass.filterset_class class
    attribute
    """

    filterset_class = None

    def _filter_query(self, query):
        assert self.filterset_class is not None, 'You must define a filterset'
        return self.filterset_class(query).filter()


class FilterWorkspacedMixin(ListMixin):
    """Add filter endpoint for searching on any workspaced objects columns
    """

    @route('/filter')
    def filter(self, workspace_name):
        """
        ---
        tags: [Filter, {tag_name}]
        description: Filters, sorts and groups workspaced objects using a json with parameters. These parameters must be part of the model.
        parameters:
        - in: query
          name: q
          description: recursive json with filters that supports operators. The json could also contain sort and group.
        responses:
          200:
            description: returns filtered, sorted and grouped results
            content:
              application/json:
                schema: FlaskRestlessSchema
          400:
            description: invalid q was sent to the server
        """
        filters = flask.request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters, workspace_name)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    def _generate_filter_query(self, filters, workspace, severity_count=False):
        filter_query = search(db.session,
                              self.model_class,
                              filters)

        filter_query = filter_query.filter(self.model_class.workspace == workspace)
        if severity_count and 'group_by' not in filters:
            filter_query = filter_query.options(
                undefer(self.model_class.vulnerability_critical_generic_count),
                undefer(self.model_class.vulnerability_high_generic_count),
                undefer(self.model_class.vulnerability_medium_generic_count),
                undefer(self.model_class.vulnerability_low_generic_count),
                undefer(self.model_class.vulnerability_info_generic_count),
                undefer(self.model_class.vulnerability_unclassified_generic_count),
                undefer(self.model_class.credentials_count),
                undefer(self.model_class.open_service_count),
                joinedload(self.model_class.hostnames),
                joinedload(self.model_class.services),
                joinedload(self.model_class.update_user),
                joinedload(getattr(self.model_class, 'creator')).load_only('username'),
            )
        return filter_query

    def _filter(self, filters, workspace_name, severity_count=False):
        marshmallow_params = {'many': True, 'context': {}}
        try:
            filters = FlaskRestlessSchema().load(json.loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            flask.abort(400, "Invalid filters")

        workspace = get_workspace(workspace_name)
        filter_query = None
        if 'group_by' not in filters:
            offset = 0
            limit = None
            if 'offset' in filters:
                offset = filters.pop('offset')
            if 'limit' in filters:
                limit = filters.pop('limit')
            try:
                filter_query = self._generate_filter_query(
                    filters,
                    workspace,
                    severity_count=severity_count
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)

            count = filter_query.count()
            filter_query = filter_query.limit(limit).offset(offset)

            objs = self.schema_class(**marshmallow_params).dumps(filter_query)
            return json.loads(objs), count
        else:
            try:
                filter_query = self._generate_filter_query(
                    filters,
                    workspace,
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)
            data, rows_count = get_filtered_data(filters, filter_query)
            return data, rows_count


class FilterObjects:

    def _process_filter_data(self, filters, workspace_name=None):
        filters = self._get_validated_filters_standalone(filters)
        return self._filter_standalone(filters, None, False, False, workspace_name)

    def _get_validated_filters_standalone(self, filters):
        filters_to_validate = None

        try:
            filters_to_validate = FlaskRestlessSchema().load(json.loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            flask.abort(400, "Invalid filters")

        if hasattr(self, 'fields_to_exclude'):
            if not self._validate_fields_standalone(filters_to_validate):
                flask.abort(400, "Invalid filters")

        return filters

    def _generate_filter_query_standalone(self, filters, severity_count=False, host_vulns=False, workspace=None):
        filter_query = search(db.session,
                              self.model_class,
                              filters)

        if workspace:
            filter_query = filter_query.filter(self.model_class.workspace == workspace)

        if severity_count and 'group_by' not in filters:
            filter_query = count_vulnerability_severities(filter_query, self.model_class,
                                                          all_severities=True, host_vulns=host_vulns)

            filter_query = filter_query.options(
                with_expression(
                    Workspace.vulnerability_web_count,
                    _make_vuln_count_property('vulnerability_web', use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_standard_count,
                    _make_vuln_count_property('vulnerability', use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_code_count,
                    _make_vuln_count_property('vulnerability_code', use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_confirmed_count,
                    _make_vuln_count_property(None,
                                              confirmed=True,
                                              use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_open_count,
                    _make_vuln_count_property(None,
                                              extra_query=" status!='closed' ",
                                              use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_closed_count,
                    _make_vuln_count_property(None,
                                              extra_query=" status='closed' ",
                                              use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_total_count,
                    _make_vuln_count_property(type_=None,
                                              use_column_property=False)
                )
            )

        return filter_query

    def _key_finder_standalone(self, key: str, data):
        if isinstance(data, dict):
            for k, v in data.items():
                if k == key:
                    yield v

                elif isinstance(v, dict) or isinstance(v, list):
                    yield from self._key_finder_standalone(key, v)

        elif isinstance(data, list):
            for item in data:
                yield from self._key_finder_standalone(key, item)

    def _validate_fields_standalone(self, filters: Dict[str, List[Dict]]) -> bool:
        intersection = set(self.fields_to_exclude).intersection(set(self._key_finder_standalone('name', filters)))
        return not intersection

    def _filter_standalone(self, filters: str, extra_alchemy_filters: BooleanClauseList = None,
                severity_count=False, host_vulns=False, workspace_name=None) -> Tuple[list, int]:

        marshmallow_params = {'many': True, 'context': {}}

        self.schema_class = self.schema_class or self._get_schema_class()

        try:
            filters = FlaskRestlessSchema().load(json.loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            flask.abort(400, "Invalid filters")

        workspace = get_workspace(workspace_name) if workspace_name else None

        filter_query = None
        if 'group_by' not in filters:
            offset = None
            limit = None
            if 'offset' in filters:
                offset = filters.pop('offset')
            if 'limit' in filters:
                limit = filters.pop('limit')  # we need to remove pagination, since

            try:
                filter_query = self._generate_filter_query_standalone(
                    filters,
                    severity_count=severity_count,
                    host_vulns=host_vulns,
                    workspace=workspace
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)

            if extra_alchemy_filters is not None:
                filter_query = filter_query.filter(extra_alchemy_filters)
            count = filter_query.count()
            if limit:
                filter_query = filter_query.limit(limit)
            if offset:
                filter_query = filter_query.offset(offset)
            filter_query = self._add_to_filter_standalone(filter_query)
            objs = self.schema_class(**marshmallow_params).dumps(filter_query)
            return json.loads(objs), count
        else:
            try:
                filter_query = self._generate_filter_query_standalone(
                    filters,
                    workspace=workspace
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)
            if extra_alchemy_filters is not None:
                filter_query += filter_query.filter(extra_alchemy_filters)

            data, rows_count = get_filtered_data(filters, filter_query)
            return data, rows_count

    def _add_to_filter_standalone(self, filter_query, **kwargs):
        return filter_query


class FilterMixin(ListMixin):
    """Add filter endpoint for searching on any non workspaced objects columns
    """

    @route('/filter')
    def filter(self):
        """
        ---
        tags: ["Filter", {tag_name}]
        description: Filters, sorts and groups non workspaced objects using a json with parameters. These parameters must be part of the model.
        parameters:
        - in: query
          name: q
          description: Recursive json with filters that supports operators. The json could also contain sort and group.
        responses:
          200:
            description: Returns filtered, sorted and grouped results
            content:
              application/json:
                schema: FlaskRestlessSchema
          400:
            description: Invalid q was sent to the server
        """
        filters = flask.request.args.get('q', '{"filters": []}')
        filtered_objs, count = self._filter(filters)

        class PageMeta:
            total = 0

        pagination_metadata = PageMeta()
        pagination_metadata.total = count
        return self._envelope_list(filtered_objs, pagination_metadata)

    def _generate_filter_query(
            self, filters, severity_count=False, host_vulns=False, only_total_vulns=False, list_view=False
    ):

        filter_query = search(db.session,
                              self.model_class,
                              filters)
        # TODO: Refactor all stats
        if only_total_vulns:
            filter_query = filter_query.options(
                with_expression(
                    Workspace.vulnerability_total_count,
                    _make_vuln_count_property(type_=None,
                                              use_column_property=False)
                ),
                joinedload(Workspace.scope),
                joinedload(Workspace.allowed_users),
            )
            return filter_query

        if list_view:
            filter_query = filter_query.options(
                with_expression(
                    Workspace.vulnerability_total_count,
                    _make_vuln_count_property(type_=None,
                                              use_column_property=False)
                ),
                with_expression(
                    Workspace.host_count,
                    _make_generic_count_property('workspace', 'host', use_column_property=False)
                ),
                with_expression(
                    Workspace.total_service_count,
                    _make_generic_count_property('workspace', 'service', use_column_property=False)
                ),
                joinedload(Workspace.scope),
                joinedload(Workspace.allowed_users),
            )
            return filter_query

        if severity_count and 'group_by' not in filters:
            # TODO: Refactor all stats
            filter_query = count_vulnerability_severities(filter_query, self.model_class,
                                                          all_severities=True, host_vulns=host_vulns)
            filter_query = filter_query.options(
                with_expression(
                    Workspace.vulnerability_web_count,
                    _make_vuln_count_property('vulnerability_web', use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_standard_count,
                    _make_vuln_count_property('vulnerability', use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_code_count,
                    _make_vuln_count_property('vulnerability_code', use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_confirmed_count,
                    _make_vuln_count_property(None,
                                              confirmed=True,
                                              use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_open_count,
                    _make_vuln_count_property(None,
                                              extra_query=" status!='closed' ",
                                              use_column_property=False),
                ),
                with_expression(
                    Workspace.vulnerability_closed_count,
                    _make_vuln_count_property(None,
                                              extra_query=" status='closed' ",
                                              use_column_property=False)
                ),
                with_expression(
                    Workspace.vulnerability_total_count,
                    _make_vuln_count_property(type_=None,
                                              use_column_property=False)
                ),
                with_expression(
                     Workspace.credential_count,
                     _make_generic_count_property('workspace', 'credential', use_column_property=False)
                ),
                with_expression(
                    Workspace.host_count,
                    _make_generic_count_property('workspace', 'host', use_column_property=False)
                ),
                with_expression(
                    Workspace.total_service_count,
                    _make_generic_count_property('workspace', 'service', use_column_property=False)
                ),
                joinedload(Workspace.scope),
                joinedload(Workspace.allowed_users),
            )

        return filter_query

    def _filter(self, filters: str, extra_alchemy_filters: BooleanClauseList = None,
                severity_count=False, host_vulns=False, exclude=[], only_total_vulns=False,
                list_view=False, return_objects=False) -> Tuple[list, int]:
        marshmallow_params = {'many': True, 'context': {}, 'exclude': exclude}
        try:
            filters = FlaskRestlessSchema().load(json.loads(filters)) or {}
        except (ValidationError, JSONDecodeError) as ex:
            logger.exception(ex)
            flask.abort(400, "Invalid filters")

        filter_query = None
        if 'group_by' not in filters:
            offset = 0
            limit = None
            if 'offset' in filters:
                offset = filters.pop('offset')
            if 'limit' in filters:
                limit = filters.pop('limit')
            try:
                filter_query = self._generate_filter_query(
                    filters,
                    severity_count=severity_count,
                    host_vulns=host_vulns,
                    only_total_vulns=only_total_vulns,
                    list_view=list_view
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)

            if extra_alchemy_filters is not None:
                filter_query = filter_query.filter(extra_alchemy_filters)
            count = filter_query.order_by(None).count()
            if limit:
                filter_query = filter_query.limit(limit)
            if offset:
                filter_query = filter_query.offset(offset)
            filter_query = self._add_to_filter(filter_query)
            if return_objects:
                return filter_query.all(), filter_query.count()
            objs = self.schema_class(**marshmallow_params).dumps(filter_query)
            return json.loads(objs), count
        else:
            try:
                filter_query = self._generate_filter_query(
                    filters,
                )
            except TypeError as e:
                flask.abort(400, e)
            except AttributeError as e:
                flask.abort(400, e)

            if extra_alchemy_filters is not None:
                filter_query += filter_query.filter(extra_alchemy_filters)

            data, rows_count = get_filtered_data(filters, filter_query)
            return data, rows_count

    def _add_to_filter(self, filter_query, **kwargs):
        return filter_query


class ListWorkspacedMixin(ListMixin):
    """Add GET /<workspace_name>/<route_base>/ route"""
    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough


class RetrieveMixin:
    """Add GET /<id>/ route"""

    def get(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Retrieves {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        return self._dump(self._get_object(object_id, eagerload=True,
                                           **kwargs), kwargs)


class RetrieveWorkspacedMixin(RetrieveMixin):
    """Add GET /<workspace_name>/<route_base>/<id>/ route"""

    # There are no differences with the non-workspaced implementations. The code
    # inside the view generic methods is enough
    def get(self, object_id, workspace_name=None):
        """
        ---
          tags: ["{tag_name}"]
          summary: Retrieves {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().get(object_id, workspace_name=workspace_name)


class RetrieveMultiWorkspacedMixin(RetrieveWorkspacedMixin):
    """Control GET /<workspace_name>/<route_base>/<id>/ route"""


class ReadOnlyView(SortableMixin,
                   ListMixin,
                   RetrieveMixin,
                   GenericView):
    """A generic view with list and retrieve endpoints

    It is just a GenericView inheriting also from ListMixin,
    RetrieveMixin and SortableMixin.
    """


class ReadOnlyWorkspacedView(SortableMixin,
                             ListWorkspacedMixin,
                             RetrieveWorkspacedMixin,
                             GenericWorkspacedView):
    """A workspaced generic view with list and retrieve endpoints

    It is just a GenericWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveWorkspacedMixin and SortableMixin"""


class ReadOnlyMultiWorkspacedView(SortableMixin,
                                  ListWorkspacedMixin,
                                  RetrieveMultiWorkspacedMixin,
                                  GenericMultiWorkspacedView):
    """A multi workspaced generic view with list and retrieve endpoints

    It is just a GenericMultiWorkspacedView inheriting also from
    ListWorkspacedMixin, RetrieveMultiWorkspacedMixin and SortableMixin"""


class CreateMixin:
    """Add POST / route"""

    def post(self, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Creates {class_model}
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        context = {'updating': False}

        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        data.pop('id', None)
        created = self._perform_create(data, **kwargs)
        if not flask_login.current_user.is_anonymous:
            created.creator = flask_login.current_user
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
            logger.info(f"{obj} created")
        except sqlalchemy.exc.IntegrityError as ex:
            logger.info(f"Couldn't create {obj}")
            if not is_unique_constraint_violation(ex):
                if not_null_constraint_violation(ex):
                    flask.abort(flask.make_response({'message': 'Be sure to send all required parameters.'}, 400))
                else:
                    raise
            db.session.rollback()
            conflict_obj = get_conflict_object(db.session, obj, data)
            if conflict_obj:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            else:
                raise
        return obj


class CommandMixin:
    """
        Created the command obj to log model activity after a command
        execution via the api (ex. from plugins)
        This will use GET parameter command_id.
        NOTE: GET parameters are also available in POST requests
    """

    @staticmethod
    def _set_command_id(obj, created):
        try:
            # validates the data type from user input.
            command_id = int(flask.request.args.get('command_id', None))
        except TypeError:
            command_id = None

        if command_id:
            command = db.session.query(Command).filter(Command.id == command_id,
                                                       Command.workspace == obj.workspace).first()
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

    def post(self, workspace_name=None):
        """
        ---
          tags: ["{tag_name}"]
          summary: Creates {class_model}
          parameters:
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            201:
              description: Created
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().post(workspace_name=workspace_name)

    def _perform_create(self, data, workspace_name):
        assert not db.session.new
        workspace = get_workspace(workspace_name)
        obj = self.model_class(**data)
        obj.workspace = workspace
        # assert not db.session.new
        try:
            db.session.add(obj)
            db.session.commit()
            logger.info(f"{obj} created")
        except sqlalchemy.exc.IntegrityError as ex:
            logger.info(f"Couldn't create {obj}")
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = get_workspace(workspace_name)
            conflict_obj = get_conflict_object(db.session, obj, data, workspace)
            if conflict_obj:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            else:
                raise

        self._set_command_id(obj, True)
        return obj


class UpdateMixin:
    """Add PUT /<id>/ route"""

    def put(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """

        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context),
                                flask.request)
        # just in case an schema allows id as writable.
        data.pop('id', None)

        self._update_object(obj, data, partial=False)
        self._perform_update(object_id, obj, data, **kwargs)

        return self._dump(obj, kwargs), 200

    def _update_object(self, obj, data, **kwargs):
        """Perform changes in the selected object

        It modifies the attributes of the SQLAlchemy model to match
        the data passed by the Marshmallow schema.

        It is common to overwrite this method to do something strange
        with some specific field. Typically the new method should call
        this one to handle the update of the rest of the fields.
        """
        for (key, value) in data.items():
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, **kwargs):
        """Commit the SQLAlchemy session, check for updating conflicts"""
        try:
            db.session.add(obj)
            db.session.commit()
            logger.info(f"{obj} updated")
        except sqlalchemy.exc.IntegrityError as ex:
            logger.info(f"Couldn't update {obj}")
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
                            conflict_obj),
                    }
                ))
            else:
                raise
        return obj

    def patch(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        exclude = kwargs.pop('exclude', [])
        obj = self._get_object(object_id, **kwargs)
        context = {'updating': True, 'object': obj}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context, partial=True),
                                flask.request)
        # just in case an schema allows id as writable.
        data.pop('id', None)
        self._update_object(obj, data, partial=True)
        self._perform_update(object_id, obj, data, partial=True, **kwargs)

        return self._dump(obj, kwargs, exclude=exclude), 200


class BulkUpdateMixin(FilterObjects):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['PATCH'])
    def bulk_update(self, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Update a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        workspace_name = kwargs.get('workspace_name') if 'workspace_name' in kwargs else None

        # Try to get ids
        if flask.request.json and 'ids' in flask.request.json:
            ids = list(filter(lambda x: type(x) is self.lookup_field_type, flask.request.json['ids']))

        # Try filter if no ids
        elif flask.request.args.get('q', None) is not None:
            filtered_objects = self._process_filter_data(flask.request.args.get('q', '{"filters": []}'), workspace_name)
            ids = list(x.get("obj_id") for x in filtered_objects[0])
        else:
            flask.abort(400)

        objects = self._get_objects(ids, **kwargs)
        context = {'updating': True, 'objects': objects}
        data = self._parse_data(self._get_schema_instance(kwargs, context=context, partial=True),
                                flask.request)
        # just in case an schema allows id as writable.
        data.pop('id', None)
        data.pop('ids', None)

        return self._perform_bulk_update(ids, data, **kwargs), 200

    def _bulk_update_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        return self.model_class.query.filter(self.model_class.id.in_(ids))

    def _pre_bulk_update(self, data, **kwargs):
        return {}

    def _post_bulk_update(self, ids, extracted_data, workspace_name=None, data=None, **kwargs):
        pass

    def _perform_bulk_update(self, ids, data, workspace_name=None, **kwargs):
        try:
            post_bulk_update_data = self._pre_bulk_update(data, workspace_name=workspace_name, **kwargs)
            if (len(data) > 0 or len(post_bulk_update_data) > 0) and len(ids) > 0:
                returns = None
                _time = time.time()
                if 'returning' in kwargs:
                    returns = db.session.execute(sqlalchemy.update(self.model_class)
                                                 .where(self.model_class.id.in_(ids))
                                                 .values(data).returning(*kwargs['returning']))
                    returns = returns.fetchall()
                    updated = len(returns)
                else:
                    queryset = self._bulk_update_query(ids, workspace_name=workspace_name, **kwargs)
                    updated = queryset.update(data, synchronize_session='fetch')
                logger.debug(f"Updated {updated} {self.model_class.__name__} in {time.time() - _time} seconds")
                self._post_bulk_update(ids, post_bulk_update_data, workspace_name=workspace_name, data=data, returning=returns)
            else:
                updated = 0
            db.session.commit()
            response = {'updated': updated}
            return flask.jsonify(response)
        except ValueError as e:
            db.session.rollback()
            flask.abort(400, ValidationError(
               {
                   'message': str(e),
               }
            ))
        except sqlalchemy.exc.IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                raise
            db.session.rollback()
            workspace = None
            if workspace_name:
                workspace = db.session.query(Workspace).filter_by(name=workspace_name).first()
            conflict_obj = get_conflict_object(db.session, self.model_class(), data, workspace, ids)
            if conflict_obj is not None:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Existing value',
                        'object': self._get_schema_class()().dump(
                            conflict_obj),
                    }
                ))
            elif len(ids) >= 2:
                flask.abort(409, ValidationError(
                    {
                        'message': 'Updating more than one object with unique data',
                        'data': data
                    }
                ))
            else:
                raise


class UpdateWorkspacedMixin(UpdateMixin, CommandMixin):
    """Add PUT /<workspace_name>/<route_base>/<id>/ route

    If a GET parameter command_id is passed, it will create a new
    CommandObject associated to that command to register the change in
    the database.
    """

    def put(self, object_id, workspace_name=None, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().put(object_id, workspace_name=workspace_name, **kwargs)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False):
        # # Make sure that if I created new objects, I had properly committed them
        # assert not db.session.new

        with db.session.no_autoflush:
            obj.workspace = get_workspace(workspace_name)

        self._set_command_id(obj, False)
        return super()._perform_update(object_id, obj, data, workspace_name)

    def patch(self, object_id, workspace_name=None, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Updates {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
              type: integer
          - in: path
            name: workspace_name
            required: true
            schema:
              type: string
          requestBody:
            required: true
            content:
              application/json:
                schema: {schema_class}
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            409:
              description: Duplicated key found
              content:
                application/json:
                  schema: {schema_class}
        """
        return super().patch(object_id, workspace_name=workspace_name, **kwargs)


class BulkUpdateWorkspacedMixin(BulkUpdateMixin):

    @route('', methods=['PATCH'])
    def bulk_update(self, workspace_name, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        return super().bulk_update(workspace_name=workspace_name)

    def _bulk_update_query(self, ids, **kwargs):
        workspace = get_workspace(kwargs["workspace_name"])
        return super()._bulk_update_query(ids).filter(self.model_class.workspace_id == workspace.id)


class DeleteMixin:
    """Add DELETE /<id>/ route"""

    def delete(self, object_id, **kwargs):
        """
        ---
          tags: ["{tag_name}"]
          summary: Deletes {class_model}
          parameters:
          - in: path
            name: object_id
            required: true
            schema:
                type: integer
          responses:
            204:
              description: The resource was deleted successfully
        """
        obj = self._get_object(object_id, **kwargs)
        self._perform_delete(obj, **kwargs)
        # TODO: Check _post_delete def differences with corp
        return None, 204

    def _perform_delete(self, obj, workspace_name=None):
        db.session.delete(obj)
        db.session.commit()
        logger.info(f"{obj} deleted")


class BulkDeleteMixin(FilterObjects):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['DELETE'])
    def bulk_delete(self, *args, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        # TODO BULK_DELETE_SCHEMA
        # Try to get ids
        if flask.request.json and 'ids' in flask.request.json:
            ids = list(filter(lambda x: type(x) is self.lookup_field_type, flask.request.json['ids']))

        # Try filter if no ids
        elif flask.request.args.get('q', None) is not None:
            filtered_objects = self._process_filter_data(flask.request.args.get('q', '{"filters": []}'))
            ids = list(x.get("id") for x in filtered_objects[0])
        else:
            flask.abort(400)
        # TODO: Check _post_bulk_delete with corp
        return self._perform_bulk_delete(ids, **kwargs), 200

    def _bulk_delete_query(self, ids, **kwargs):
        # It IS better to as is but warn of ON CASCADE
        return self.model_class.query.filter(self.model_class.id.in_(ids))

    def _perform_bulk_delete(self, values, **kwargs):
        deleted = self._bulk_delete_query(values, **kwargs).delete(synchronize_session='fetch')
        db.session.commit()
        response = {'deleted': deleted}
        return flask.jsonify(response)


class DeleteWorkspacedMixin(DeleteMixin):
    """Add DELETE /<workspace_name>/<route_base>/<id>/ route"""

    def delete(self, object_id, workspace_name=None):
        """
          ---
            tags: ["{tag_name}"]
            summary: Deletes {class_model}
            parameters:
            - in: path
              name: object_id
              required: true
              schema:
                type: integer
            - in: path
              name: workspace_name
              required: true
              schema:
                type: string
            responses:
              204:
                description: The resource was deleted successfully
        """
        return super().delete(object_id, workspace_name=workspace_name)

    def _perform_delete(self, obj, workspace_name=None):
        with db.session.no_autoflush:
            obj.workspace = get_workspace(workspace_name)
        return super()._perform_delete(obj, workspace_name)


class BulkDeleteWorkspacedMixin(BulkDeleteMixin):
    # These mixin should be merged with DeleteMixin after v2 is removed

    @route('', methods=['DELETE'])
    def bulk_delete(self, workspace_name, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Delete a group of {class_model} by ids."
          responses:
            204:
              description: Ok
        """
        return super().bulk_delete(workspace_name=workspace_name)

    def _bulk_delete_query(self, ids, **kwargs):
        workspace = get_workspace(kwargs.pop("workspace_name"))
        return super()._bulk_delete_query(ids).filter(self.model_class.workspace_id == workspace.id)


class CountWorkspacedMixin:
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
        """
          ---
          tags: [{tag_name}]
          summary: "Group {class_model} by the field set in the group_by GET parameter."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            404:
              description: group_by is not specified
        """
        res = {
            'groups': [],
            'total_count': 0
        }
        group_by, sort_dir = get_group_by_and_sort_dir(self.model_class)

        workspace_name = kwargs.pop('workspace_name')
        # using format is not a great practice.
        # the user input is group_by, however it's filtered by column name.
        table_name = inspect(self.model_class).tables[0].name
        group_by = f'{table_name}.{group_by}'

        query_count = self._filter_query(
            db.session.query(self.model_class).
            join(Workspace).
            group_by(group_by).
            filter(Workspace.name == workspace_name,
                   *self.count_extra_filters)
        )

        # order
        order_by = group_by
        if sort_dir == 'desc':
            query_count = query_count.order_by(desc(order_by))
        else:
            query_count = query_count.order_by(asc(order_by))
        for key, query_count in query_count.values(group_by, func.count(group_by)):
            res['groups'].append(
                {'count': query_count,
                 'name': key,
                 # To add compatibility with the web ui
                 flask.request.args.get('group_by'): key,
                 }
            )
            res['total_count'] += query_count
        return res


class CountMultiWorkspacedMixin:
    """Add GET /<workspace_name>/<route_base>/count_multi_workspace/ route

    Receives a list of workspaces separated by comma in the workspaces
    GET parameter.
    If no workspace is specified, the view will return a 400 error.

    Group objects by the field set in the group_by GET parameter. If it
    isn't specified, the view will return a 400 error. For each group,
    show the count of elements and its value.

    This view is often used by some parts of the web UI. It was designed
    to keep backwards compatibility with the count endpoint of Faraday
    v2.
    """

    #: List of SQLAlchemy query filters to apply when counting
    count_extra_filters = []

    def count_multi_workspace(self, **kwargs):
        """
        ---
          tags: [{tag_name}]
          summary: "Count {class_model} by multiples workspaces"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            400:
              description: No workspace passed or group_by is not specified
        """
        # """head:
        #  tags: [{tag_name}]
        #   responses:
        #     200:
        #       description: Ok
        # options:
        #   tags: [{tag_name}]
        #   responses:
        #     200:
        #       description: Ok
        # """
        res = {
            'groups': defaultdict(dict),
            'total_count': 0
        }

        workspace_names_list = flask.request.args.get('workspaces', None)

        if not workspace_names_list:
            flask.abort(400, {"message": "workspaces is a required parameter"})

        workspace_names_list = workspace_names_list.split(',')

        # Enforce workspace permission checking for each workspace
        for workspace_name in workspace_names_list:
            get_workspace(workspace_name)

        group_by, sort_dir = get_group_by_and_sort_dir(self.model_class)

        grouped_attr = getattr(self.model_class, group_by)

        q = db.session.query(
            Workspace.name,
            grouped_attr,
            func.count(grouped_attr)
        ) \
            .join(Workspace) \
            .group_by(grouped_attr, Workspace.name) \
            .filter(Workspace.name.in_(workspace_names_list))

        # order
        order_by = grouped_attr
        if sort_dir == 'desc':
            q = q.order_by(desc(Workspace.name), desc(order_by))
        else:
            q = q.order_by(asc(Workspace.name), asc(order_by))

        for workspace, key, count in q.all():
            res['groups'][workspace][key] = count
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


class CustomModelConverter(ModelConverter):
    """
    Model converter that automatically sets minimum length
    validators to not blankable fields
    """

    def _add_column_kwargs(self, kwargs, column):
        super()._add_column_kwargs(kwargs, column)
        if not column.info.get('allow_blank', True):
            kwargs['validate'].append(Length(min=1))


class CustomSQLAlchemyAutoSchemaOpts(SQLAlchemyAutoSchemaOpts):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.model_converter = CustomModelConverter


# Restore marshmallow's DateTime field behavior of marshmallow 2 so it adds
# "+00:00" to the serialized date. This ugly hack was done to keep our API
# backwards-compatible. Yes, it's horrible.
# Also, I'm putting it here because this file will be always imported in a very
# early stage, before defining any schemas.
# This commit broke backwards compatibility:
# https://github.com/marshmallow-code/marshmallow/commit/610ec20ea3be89684f7e4df8035d163c3561c904
# TODO check if we can remove this
def old_isoformat(dt, *args, **kwargs):
    """Return the ISO8601-formatted UTC representation of a datetime object."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    else:
        dt = dt.astimezone(datetime.timezone.utc)
    return dt.isoformat(*args, **kwargs)


fields.DateTime.SERIALIZATION_FUNCS['iso'] = old_isoformat


class AutoSchema(Schema, metaclass=SQLAlchemyAutoSchemaMeta):
    """
    A Marshmallow schema that does field introspection based on
    the SQLAlchemy model specified in Meta.model.
    Unlike the marshmallow_sqlalchemy ModelSchema, it doesn't change
    the serialization and deserialization process.
    """
    OPTIONS_CLASS = CustomSQLAlchemyAutoSchemaOpts

    # Use NullToBlankString instead of fields.String by default on text fields
    TYPE_MAPPING = Schema.TYPE_MAPPING.copy()
    TYPE_MAPPING[str] = NullToBlankString

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unknown = EXCLUDE


class FilterAlchemyModelConverter(ModelConverter):
    """Use this to make all fields of a model not required.

    It is used to make FilterAlchemy support not nullable columns"""

    def _add_column_kwargs(self, kwargs, column):
        super()._add_column_kwargs(kwargs, column)
        kwargs['required'] = False


class AutoSchemaFlaskParser(FlaskParser):
    # It is required to use a schema class that has unknown=EXCLUDE by default.
    # Otherwise, requests would fail if a not defined query parameter is sent
    # (like group_by)
    DEFAULT_SCHEMA_CLASS = AutoSchema


class FilterSetMeta:
    """Base Meta class of FilterSet objects"""
    parser = AutoSchemaFlaskParser(location='query')
    converter = FilterAlchemyModelConverter()


def get_user_permissions(user):
    permissions = defaultdict(dict)

    # Hardcode all permissions to allowed
    ALLOWED = {'allowed': True, 'reason': None}

    # TODO schema
    generic_entities = {
        'licences', 'methodology_templates', 'task_templates', 'users',
        'vulnerability_template', 'workspaces',
        'agents', 'agents_schedules', 'commands', 'comments', 'hosts',
        'executive_reports', 'services', 'methodologies', 'tasks', 'vulns',
        'credentials',
    }

    for entity in generic_entities:
        permissions[entity]['view'] = ALLOWED
        permissions[entity]['create'] = ALLOWED
        permissions[entity]['update'] = ALLOWED
        permissions[entity]['delete'] = ALLOWED

    extra_permissions = {
        'vulns.status_change',
        'settings.view',
        'settings.update',
        'ticketing.jira',
        'ticketing.servicenow',
        'bulk_create.bulk_create',
        'agents.run',
        'workspace_comparison.compare',
        'data_analysis.view',
    }

    for permission in extra_permissions:
        (entity, action) = permission.split('.')
        permissions[entity][action] = ALLOWED

    return permissions


class ContextMixin(ReadOnlyView):

    count_extra_filters = []

    def _get_base_query(self, operation="", *args, **kwargs):
        if not operation:
            operation = "read" if flask.request.method in ['GET', 'HEAD', 'OPTIONS'] else "write"
        query = super()._get_base_query(*args, **kwargs)
        return self._apply_filter_context(query, operation)

    def _apply_filter_context(self, query, operation="read"):
        filters = and_()
        if operation == "write":
            filters = filters & self._get_context_write_filter()
        query = query.filter(
            self.model_class.workspace_id.in_(
                self._get_context_workspace_ids(filters)
            )
        )
        return query

    @staticmethod
    def _get_context_workspace_ids(filter):
        return db.session.query(Workspace.id)\
            .join(WorkspacePermission, Workspace.id == WorkspacePermission.workspace_id, isouter=True)\
            .filter(filter).all()

    @staticmethod
    def _get_context_workspace_filter():
        return (
                (WorkspacePermission.user_id == flask_login.current_user.id) | (Workspace.public == True) # noqa: E712, E261
        )

    @staticmethod
    def _get_context_write_filter():
        return (
                Workspace.readonly == False # noqa: E712, E261
        )

    def _get_context_workspace_query(self, operation="write"):
        workspace_query = Workspace.query
        return workspace_query

    def _bulk_delete_query(self, ids, **kwargs):
        return self._get_base_query(operation="write", **kwargs).filter(self.model_class.id.in_(ids))

    def _bulk_update_query(self, ids, **kwargs):
        return self._get_base_query(operation="write", **kwargs).filter(self.model_class.id.in_(ids))

    def count(self, **kwargs):
        """
          ---
          tags: [{tag_name}]
          summary: "Group {class_model} by the field set in the group_by GET parameter."
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: {schema_class}
            404:
              description: group_by is not specified
        """
        res = {
            'groups': [],
            'total_count': 0
        }
        group_by, sort_dir = get_group_by_and_sort_dir(self.model_class)

        # using format is not a great practice.
        # the user input is group_by, however it's filtered by column name.
        table_name = inspect(self.model_class).tables[0].name
        group_by = f'{table_name}.{group_by}'

        query_count = self._apply_filter_context(
            self._filter_query(
                db.session.query(self.model_class).
                group_by(group_by).
                filter(*self.count_extra_filters)
            )
        )
        # order
        order_by = group_by
        if sort_dir == 'desc':
            query_count = query_count.order_by(desc(order_by))
        else:
            query_count = query_count.order_by(asc(order_by))
        for key, query_count in query_count.values(group_by, func.count(group_by)):
            res['groups'].append(
                {'count': query_count,
                 'name': key,
                 # To add compatibility with the web ui
                 flask.request.args.get('group_by'): key,
                 }
            )
            res['total_count'] += query_count
        return res
