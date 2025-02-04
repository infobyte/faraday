"""
    flask.ext.restless.search
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    Provides querying, searching, and function evaluation on SQLAlchemy models.

    The most important functions in this module are the :func:`create_query`
    and :func:`search` functions, which create a SQLAlchemy query object and
    execute that query on a given model, respectively.

    :copyright: 2011 by Lincoln de Sousa <lincoln@comum.org>
    :copyright: 2012, 2013, 2014, 2015 Jeffrey Finkelstein
                <jeffrey.finkelstein@gmail.com> and contributors.
    :license: GNU AGPLv3+ or BSD

"""
# Standard library imports
import inspect
import logging
from datetime import date

# Related third party imports
from sqlalchemy import (
    and_,
    or_,
    func,
    nullsfirst,
    nullslast,
    inspect as sqlalchemy_inspect, text,
)
from sqlalchemy.ext.associationproxy import AssociationProxy
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import ColumnProperty
from sqlalchemy.orm.attributes import InstrumentedAttribute, QueryableAttribute

# Local application imports
from faraday.server.models import (
    User,
    CVE,
    Role,
    CustomFieldsSchema,
    VulnerabilityGeneric,
    Vulnerability,
    VulnerabilityWeb,
)

VULNERABILITY_MODELS = (Vulnerability, VulnerabilityWeb, VulnerabilityGeneric)

logger = logging.getLogger(__name__)

bind_counter = 0


def get_bind_counter():
    return bind_counter


def increment_bind_counter():
    global bind_counter
    bind_counter += 1


def reset_bind_counter():
    global bind_counter
    bind_counter = 0


def session_query(session, model):
    """Returns a SQLAlchemy query object for the specified `model`.
    If `model` has a ``query`` attribute already, ``model.query`` will be
    returned. If the ``query`` attribute is callable ``model.query()`` will be
    returned instead.
    If `model` has no such attribute, a query based on `session` will be
    created and returned.
    """
    if hasattr(model, 'query'):
        if callable(model.query):
            query = model.query()
        else:
            query = model.query
        if hasattr(query, 'filter'):
            return query
    return session.query(model)


def get_related_association_proxy_model(attr):
    """Returns the model class specified by the given SQLAlchemy relation
    attribute, or ``None`` if no such class can be inferred.
    `attr` must be a relation attribute corresponding to an association proxy.
    """
    prop = attr.remote_attr.property
    for attribute in ('mapper', 'parent'):
        if hasattr(prop, attribute):
            return getattr(prop, attribute).class_
    return None


def primary_key_names(model):
    """Returns all the primary keys for a model."""
    return [key for key, field in inspect.getmembers(model)
            if isinstance(field, QueryableAttribute)
            and isinstance(field.property, ColumnProperty)
            and field.property.columns[0].primary_key]


def _sub_operator(model, argument, fieldname):
    """Recursively calls :func:`QueryBuilder._create_operation` when argument
    is a dictionary of the form specified in :ref:`search`.

    This function is for use with the ``has`` and ``any`` search operations.

    """
    submodel = None
    if isinstance(model, InstrumentedAttribute):
        submodel = model.property.mapper.class_
    elif isinstance(model, AssociationProxy):
        submodel = get_related_association_proxy_model(model)
    else:  # TODO what to do here?
        logger.warning('Case not handled {0} {1} {2}', model, argument, fieldname)
    if isinstance(argument, dict):
        fieldname = argument['name']
        operator = argument['op']
        argument = argument.get('val')
        relation = None
        if '__' in fieldname:
            fieldname, relation = fieldname.split('__')
        return QueryBuilder._create_operation(submodel, fieldname, operator, argument, relation)
    # Support legacy has/any with implicit eq operator
    return getattr(submodel, fieldname) == argument


#: The mapping from operator name (as accepted by the search method) to a
#: function which returns the SQLAlchemy expression corresponding to that
#: operator.
#:
#: Each of these functions accepts either one, two, or three arguments. The
#: first argument is the field object on which to apply the operator. The
#: second argument, where it exists, is either the second argument to the
#: operator or a dictionary as described below. The third argument, where it
#: exists, is the name of the field.
#:
#: For functions that accept three arguments, the second argument may be a
#: dictionary containing ``'name'``, ``'op'``, and ``'val'`` mappings so that
#: :func:`QueryBuilder._create_operation` may be applied recursively. For more
#: information and examples, see :ref:`search`.
#:
#: Some operations have multiple names. For example, the equality operation can
#: be described by the strings ``'=='``, ``'eq'``, ``'equals'``, etc.
OPERATORS = {
    # Operators which accept a single argument.
    'is_null': lambda f: f == None,  # noqa E711
    'is_not_null': lambda f: f != None,  # noqa E711
    'desc': lambda f: f.desc,
    'asc': lambda f: f.asc,
    # Operators which accept two arguments.
    '==': lambda f, a: f == a,
    'eq': lambda f, a: f == a,
    'equals': lambda f, a: f == a,
    'equal_to': lambda f, a: f == a,
    '!=': lambda f, a: f != a,
    'ne': lambda f, a: f != a,
    'neq': lambda f, a: f != a,
    'not_equal_to': lambda f, a: f != a,
    'does_not_equal': lambda f, a: f != a,
    '>': lambda f, a: f > a,
    'gt': lambda f, a: f > a,
    '<': lambda f, a: f < a,
    'lt': lambda f, a: f < a,
    '>=': lambda f, a: f >= a,
    'ge': lambda f, a: f >= a,
    'gte': lambda f, a: f >= a,
    'geq': lambda f, a: f >= a,
    '<=': lambda f, a: f <= a,
    'le': lambda f, a: f <= a,
    'lte': lambda f, a: f <= a,
    'leq': lambda f, a: f <= a,
    'ilike': lambda f, a: f.ilike(a),
    'like': lambda f, a: f.like(a),
    'in': lambda f, a: f.in_(a),
    'not_in': lambda f, a: ~f.in_(a),
    # Operators which accept three arguments.
    'has': lambda f, a, fn: f.has(_sub_operator(f, a, fn)),
    'any': lambda f, a, fn: f.any(_sub_operator(f, a, fn)),
    'not_any': lambda f, a, fn: ~f.any(_sub_operator(f, a, fn)),
    # Custom operator for json fields
    'json': lambda f: f,
}


def get_json_operator(operator):
    operator_mapping = {
        '==': ('=', 'compare'),
        'eq': ('=', 'compare'),
        'equals': ('=', 'compare'),
        'equal_to': ('=', 'compare'),
        '!=': ('<>', 'compare'),
        'ne': ('<>', 'compare'),
        'neq': ('<>', 'compare'),
        'not_equal_to': ('<>', 'compare'),
        'does_not_equal': ('<>', 'compare'),
        '<': ('<', 'compare'),
        'lt': ('<', 'compare'),
        '<=': ('<=', 'compare'),
        'le': ('<=', 'compare'),
        'lte': ('<=', 'compare'),
        'leq': ('<=', 'compare'),
        '>': ('>', 'compare'),
        'gt': ('>', 'compare'),
        '>=': ('>=', 'compare'),
        'ge': ('>=', 'compare'),
        'gte': ('>=', 'compare'),
        'geq': ('>=', 'compare'),
        'like': ('LIKE', 'compare'),
        'ilike': ('ILIKE', 'compare'),
        'any': ('@>', 'any'),
        'not_any': ('@>', 'not_any'),
        'is_null': ('IS NULL', 'exists'),
        'is_not_null': ('IS NOT NULL', 'exists'),
    }

    return operator_mapping.get(operator, None)


def get_json_query(table, field, op, op_type, counter):
    if op_type == 'compare':
        return f"({table}.{field} ->> :key_{counter}) {op} :value_{counter}"  # nosec
    elif op_type == 'compare_int':
        return f"({table}.{field} ->> :key_{counter})::int {op} :value_{counter}"  # nosec
    elif op_type == 'exists':
        return f"{table}.{field} ->> :key_{counter} {op}"  # nosec
    elif op_type == 'any':
        return f"{table}.{field} -> :key_{counter} {op} :value_{counter}"  # nosec
    elif op_type == 'not_any':
        return f"NOT {table}.{field} -> :key_{counter} {op} :value_{counter} OR {table}.{field} -> :key_{counter} IS NULL"  # nosec
    elif op_type == 'list_contains':
        return f"EXISTS (SELECT 1 FROM jsonb_array_elements_text({table}.{field} -> :key_{counter}) AS element WHERE element {op} :value_{counter})"  # nosec
    elif op_type == 'date':
        return f"({table}.{field} ->> :key_{counter})::DATE {op} :value_{counter}"  # nosec
    else:
        raise TypeError('Invalid filters')


class OrderBy:
    """Represents an "order by" in a SQL query expression."""

    def __init__(self, field, direction='asc'):
        """Instantiates this object with the specified attributes.

        `field` is the name of the field by which to order the result set.

        `direction` is either ``'asc'`` or ``'desc'``, for "ascending" and
        "descending", respectively.

        """
        self.field = field
        self.direction = direction

    def __repr__(self):
        """Returns a string representation of this object."""
        return f'<OrderBy {self.field}, {self.direction}>'


class GroupBy:
    """Represents a "group by" in a SQL query expression."""

    def __init__(self, field):
        """Instantiates this object with the specified attributes.

        `field` is the name of the field by which to group the result set.

        """
        self.field = field

    def __repr__(self):
        """Returns a string representation of this object."""
        return f'<GroupBy {self.field}>'


class Filter:
    """Represents a filter to apply to a SQL query.

    A filter can be, for example, a comparison operator applied to a field of a
    model and a value or a comparison applied to two fields of the same
    model. For more information on possible filters, see :ref:`search`.

    """

    def __init__(self, fieldname, operator, argument=None, otherfield=None):
        """Instantiates this object with the specified attributes.

        `fieldname` is the name of the field of a model which will be on the
        left side of the operator.

        `operator` is the string representation of an operator to apply. The
        full list of recognized operators can be found at :ref:`search`.

        If `argument` is specified, it is the value to place on the right side
        of the operator. If `otherfield` is specified, that field on the model
        will be placed on the right side of the operator.

        .. admonition:: About `argument` and `otherfield`

           Some operators don't need either argument and some need exactly one.
           However, this constructor will not raise any errors or otherwise
           inform you of which situation you are in; it is basically just a
           named tuple. Calling code must handle errors caused by missing
           required arguments.

        """
        self.fieldname = fieldname
        self.operator = operator
        self.argument = argument
        self.otherfield = otherfield

    def __repr__(self):
        """Returns a string representation of this object."""
        return f'<Filter {self.fieldname} {self.operator} {self.argument or self.otherfield}>'

    @staticmethod
    def from_dictionary(dictionary):
        """Returns a new :class:`Filter` object with arguments parsed from
        `dictionary`.

        `dictionary` is a dictionary of the form::

            {'name': 'age', 'op': 'lt', 'val': 20}

        or::

            {'name': 'age', 'op': 'lt', 'other': 'height'}

        where ``dictionary['name']`` is the name of the field of the model on
        which to apply the operator, ``dictionary['op']`` is the name of the
        operator to apply, ``dictionary['val']`` is the value on the right to
        which the operator will be applied, and ``dictionary['other']`` is the
        name of the other field of the model to which the operator will be
        applied.

        'dictionary' may also be an arbitrary Boolean formula consisting of
        dictionaries such as these. For example::

            {'or':
                 [{'and':
                       [dict(name='name', op='like', val='%y%'),
                        dict(name='age', op='ge', val=10)]},
                  dict(name='name', op='eq', val='John')
                  ]
             }

        """
        # If there are no ANDs or ORs, we are in the base case of the
        # recursion.
        if 'or' not in dictionary and 'and' not in dictionary:
            fieldname = dictionary.get('name')
            operator = dictionary.get('op')
            argument = dictionary.get('val')
            otherfield = dictionary.get('field')
            return Filter(fieldname, operator, argument, otherfield)
        # For the sake of brevity, rename this method.
        from_dict = Filter.from_dictionary
        # If there is an OR or an AND in the dictionary, recurse on the
        # provided list of filters.
        if 'or' in dictionary:
            subfilters = dictionary.get('or')
            return DisjunctionFilter(*(from_dict(f) for f in subfilters))
        if 'and' in dictionary:
            subfilters = dictionary.get('and')
            return ConjunctionFilter(*(from_dict(f) for f in subfilters))


class JunctionFilter(Filter):
    def __init__(self, *subfilters):
        self.subfilters = subfilters

    def __iter__(self):
        return iter(self.subfilters)


class ConjunctionFilter(JunctionFilter):
    def __repr__(self):
        return f'and_{tuple(repr(f) for f in self)}'


class DisjunctionFilter(JunctionFilter):
    def __repr__(self):
        return f'or_{tuple(repr(f) for f in self)}'


class SearchParameters:
    """Aggregates the parameters for a search, including filters, search type,
    limit, offset, and order by directives.

    """

    def __init__(self, filters=None, limit=None, offset=None, order_by=None,
                 group_by=None):
        """Instantiates this object with the specified attributes.

        `filters` is a list of :class:`Filter` objects, representing filters to
        be applied during the search.

        `limit`, if not ``None``, specifies the maximum number of results to
        return in the search.

        `offset`, if not ``None``, specifies the number of initial results to
        skip in the result set.

        `order_by` is a list of :class:`OrderBy` objects, representing the
        ordering directives to apply to the result set that matches the
        search.

        `group_by` is a list of :class:`GroupBy` objects, representing the
        grouping directives to apply to the result set that matches the
        search.

        """
        self.filters = filters or []
        self.limit = limit
        self.offset = offset
        self.order_by = order_by or []
        self.group_by = group_by or []

    def __repr__(self):
        """Returns a string representation of the search parameters."""
        template = ('<SearchParameters filters={0}, order_by={1}, limit={2},'
                    ' group_by={3}, offset={4}, junction={5}>')
        return template.format(self.filters, self.order_by, self.limit,
                               self.group_by, self.offset)

    @staticmethod
    def from_dictionary(dictionary):
        """Returns a new :class:`SearchParameters` object with arguments parsed
        from `dictionary`.

        `dictionary` is a dictionary of the form::

            {
              'filters': [{'name': 'age', 'op': 'lt', 'val': 20}, ...],
              'order_by': [{'field': 'name', 'direction': 'desc'}, ...]
              'group_by': [{'field': 'age'}, ...]
              'limit': 10,
              'offset': 3,
            }

        where
        - ``dictionary['filters']`` is the list of :class:`Filter` objects
          (in dictionary form),
        - ``dictionary['order_by']`` is the list of :class:`OrderBy` objects
          (in dictionary form),
        - ``dictionary['group_by']`` is the list of :class:`GroupBy` objects
          (in dictionary form),
        - ``dictionary['limit']`` is the maximum number of matching entries to
          return,
        - ``dictionary['offset']`` is the number of initial entries to skip in
          the matching result set,

        The provided dictionary may have other key/value pairs, but they are
        ignored.

        """
        # for the sake of brevity...
        from_dict = Filter.from_dictionary
        filters = [from_dict(f) for f in dictionary.get('filters', [])]
        order_by_list = dictionary.get('order_by', [])
        order_by = [OrderBy(**o) for o in order_by_list]
        group_by_list = dictionary.get('group_by', [])
        group_by = [GroupBy(**o) for o in group_by_list]
        limit = dictionary.get('limit')
        offset = dictionary.get('offset')
        return SearchParameters(filters=filters, limit=limit, offset=offset,
                                order_by=order_by, group_by=group_by)


class QueryBuilder:
    """Provides a static function for building a SQLAlchemy query object based
    on a :class:`SearchParameters` instance.

    Use the static :meth:`create_query` method to create a SQLAlchemy query on
    a given model.

    """
    @staticmethod
    def _create_operation(model, fieldname, operator, argument, relation=None):
        """Translates an operation described as a string to a valid SQLAlchemy
        query parameter using a field or relation of the specified model.

        More specifically, this translates the string representation of an
        operation, for example ``'gt'``, to an expression corresponding to a
        SQLAlchemy expression, ``field > argument``. The recognized operators
        are given by the keys of :data:`OPERATORS`. For more information on
        recognized search operators, see :ref:`search`.

        If `relation` is not ``None``, the returned search parameter will
        correspond to a search on the field named `fieldname` on the entity
        related to `model` whose name, as a string, is `relation`.

        `model` is an instance of a SQLAlchemy declarative model being
        searched.

        `fieldname` is the name of the field of `model` to which the operation
        will be applied as part of the search. If `relation` is specified, the
        operation will be applied to the field with name `fieldname` on the
        entity related to `model` whose name, as a string, is `relation`.

        `operation` is a string representing the operation which will be
         executed between the field and the argument received. For example,
         ``'gt'``, ``'lt'``, ``'like'``, ``'in'`` etc.

        `argument` is the argument to which to apply the `operator`.

        `relation` is the name of the relationship attribute of `model` to
        which the operation will be applied as part of the search, or ``None``
        if this function should not use a related entity in the search.

        This function raises the following errors:
        * :exc:`KeyError` if the `operator` is unknown (that is, not in
          :data:`OPERATORS`)
        * :exc:`TypeError` if an incorrect number of arguments are provided for
          the operation (for example, if `operation` is `'=='` but no
          `argument` is provided)
        * :exc:`AttributeError` if no column with name `fieldname` or
          `relation` exists on `model`

        """
        if '->' in fieldname:
            if getattr(model, fieldname.split('->')[0]):
                table = 'vulnerability' if model in VULNERABILITY_MODELS else model.__tablename__

                field, key = fieldname.split('->')
                custom_field = CustomFieldsSchema.query.filter(CustomFieldsSchema.field_name == key).first()

                try:
                    op, op_type = get_json_operator(operator)
                except TypeError as e:
                    raise TypeError('Invalid filters') from e

                if op in ['like', 'ilike']:
                    if custom_field.field_type == 'list':
                        op_type = 'list_contains'

                if op_type in ['any', 'not_any']:
                    if not argument.isnumeric():
                        argument = f"\"{argument}\""

                if custom_field.field_type == 'date':
                    argument = date.fromisoformat(argument)
                    op_type = 'date'

                if op_type == 'compare':
                    if custom_field.field_type == 'int':
                        op_type = 'compare_int'

                increment_bind_counter()

                bindparams = {
                    f'key_{get_bind_counter()}': key,
                    f'value_{get_bind_counter()}': argument,
                }

                query = get_json_query(table, field, op, op_type, get_bind_counter())

                return OPERATORS['json'](text(f"{query}").bindparams(**bindparams))
        else:
            # raises KeyError if operator not in OPERATORS
            opfunc = OPERATORS[operator]
            # In Python 3.0 or later, this should be `inspect.getfullargspec`
            # because `inspect.getargspec` is deprecated.
            numargs = len(inspect.getargspec(opfunc).args)
            # raises AttributeError if `fieldname` or `relation` does not exist
            field = getattr(model, relation or fieldname)
            # each of these will raise a TypeError if the wrong number of arguments
            # is supplied to `opfunc`.
            if numargs == 1:
                return opfunc(field)
            if argument is None:
                msg = ('To compare a value to NULL, use the is_null/is_not_null '
                       'operators.')
                raise TypeError(msg)
            if numargs == 2:
                map_attr = {
                    'creator': 'username',
                }
                if hasattr(field, 'prop') and hasattr(getattr(field, 'prop'), 'entity'):
                    field = getattr(field.comparator.entity.class_, map_attr.get(field.prop.key, field.prop.key))

                return opfunc(field, argument)
            return opfunc(field, argument, fieldname)

    @staticmethod
    def _create_filter(model, filt):
        """Returns the operation on `model` specified by the provided filter.

        `filt` is an instance of the :class:`Filter` class.

        Raises one of :exc:`AttributeError`, :exc:`KeyError`, or
        :exc:`TypeError` if there is a problem creating the query. See the
        documentation for :func:`_create_operation` for more information.

        """
        # If the filter is not a conjunction or a disjunction, simply proceed
        # as normal.
        if not isinstance(filt, JunctionFilter):
            fname = filt.fieldname
            val = filt.argument
            # get the relationship from the field name, if it exists
            relation = None
            if '__' in fname:
                relation, fname = fname.split('__')
            # get the other field to which to compare, if it exists
            if filt.otherfield:
                val = getattr(model, filt.otherfield)
            # for the sake of brevity...
            create_op = QueryBuilder._create_operation
            return create_op(model, fname, filt.operator, val, relation)
        # Otherwise, if this filter is a conjunction or a disjunction, make
        # sure to apply the appropriate filter operation.
        create_filt = QueryBuilder._create_filter
        if isinstance(filt, ConjunctionFilter):
            return and_(create_filt(model, f) for f in filt)
        return or_(create_filt(model, f) for f in filt)

    @staticmethod
    def create_filters_func(model, valid_model_fields):
        create_filt = QueryBuilder._create_filter

        def create_filters(filt):
            if not isinstance(filt, JunctionFilter) and '__' in filt.fieldname:
                return create_filt(model, filt)
            else:
                if (not getattr(filt, 'fieldname', False)
                        or filt.fieldname.split('__')[0] in valid_model_fields
                        or filt.fieldname.split('->')[0] in valid_model_fields):
                    try:
                        return create_filt(model, filt)
                    except AttributeError as e:
                        # Can't create the filter since the model or submodel
                        # does not have the attribute (usually mapper)
                        raise AttributeError(f"Foreign field {filt.fieldname.split('__')[0]} "
                                             f"not found in submodel") from e
            raise AttributeError(f"Field {filt.fieldname} not found in model")

        return create_filters

    @staticmethod
    def create_query(session, model, search_params, _ignore_order_by=False):
        """Builds an SQLAlchemy query instance based on the search parameters
        present in ``search_params``, an instance of :class:`SearchParameters`.

        This method returns a SQLAlchemy query in which all matched instances
        meet the requirements specified in ``search_params``.

        `model` is SQLAlchemy declarative model on which to create a query.

        `search_params` is an instance of :class:`SearchParameters` which
        specify the filters, order, limit, offset, etc. of the query.

        If `_ignore_order_by` is ``True``, no ``order_by`` method will be
        called on the query, regardless of whether the search parameters
        indicate that there should be an ``order_by``. (This is used internally
        by Flask-Restless to work around a limitation in SQLAlchemy.)

        Building the query proceeds in this order:
        1. filtering
        2. ordering
        3. grouping
        3. limiting
        4. offsetting

        Raises one of :exc:`AttributeError`, :exc:`KeyError`, or
        :exc:`TypeError` if there is a problem creating the query. See the
        documentation for :func:`_create_operation` for more information.

        """
        # TODO: Can't this be done with group by below?
        joined_models = set()
        query = session.query(model)

        if search_params.group_by:
            select_fields = [func.count()]
            for group_by in search_params.group_by:
                field_name = group_by.field
                if '__' in field_name:
                    field_name, field_name_in_relation = field_name.split('__')
                    relation = getattr(model, field_name)
                    relation_model = relation.mapper.class_
                    field = getattr(relation_model, field_name_in_relation)
                    if relation_model not in joined_models:
                        if relation_model == User:
                            query = query.join(relation_model, model.creator_id == relation_model.id)
                        elif relation_model == CVE:
                            query = query.join(relation_model, model.cve_instances)
                        else:
                            query = query.join(relation_model)
                    joined_models.add(relation_model)
                    select_fields.append(field)
                else:
                    select_fields.append(getattr(model, group_by.field))
                query = query.with_entities(*select_fields)

        # This function call may raise an exception.
        valid_model_fields = []
        for orm_descriptor in sqlalchemy_inspect(model).all_orm_descriptors:
            if isinstance(orm_descriptor, InstrumentedAttribute):
                valid_model_fields.append(str(orm_descriptor).split('.')[1])
            if isinstance(orm_descriptor, hybrid_property):
                valid_model_fields.append(orm_descriptor.__name__)
        valid_model_fields += [str(algo).split('.')[1] for algo in sqlalchemy_inspect(model).relationships]

        filters_generator = map(   # pylint: disable=W1636
            QueryBuilder.create_filters_func(model, valid_model_fields),
            search_params.filters
        )

        filters = [filt for filt in filters_generator if filt is not None]

        # Multiple filter criteria at the top level of the provided search
        # parameters are interpreted as a conjunction (AND).
        query = query.filter(*filters)

        # Order the search. If no order field is specified in the search
        # parameters, order by primary key.
        if not _ignore_order_by:
            if search_params.order_by:
                for val in search_params.order_by:
                    field_name = val.field
                    if '__' in field_name:
                        field_name, field_name_in_relation = field_name.split('__')
                        relation = getattr(model, field_name)
                        relation_model = relation.mapper.class_
                        if relation_model not in joined_models:
                            # TODO: is it possible to guess if relationship is a many to many
                            if relation_model == Role:
                                query = query.join(relation_model, User.roles)
                            elif relation_model == User:
                                query = query.join(relation_model, model.creator_id == relation_model.id)
                            elif relation_model == CVE:
                                query = query.join(relation_model, model.cve_instances)
                            else:
                                query = query.join(relation_model, isouter=True)
                        joined_models.add(relation_model)
                        field = getattr(relation_model, field_name_in_relation)
                        direction = getattr(field, val.direction)
                        if val.direction == 'desc':
                            query = query.order_by(nullslast(direction()))
                        else:
                            query = query.order_by(nullsfirst(direction()))
                    else:
                        field = getattr(model, val.field)
                        direction = getattr(field, val.direction)
                        if val.direction == 'desc':
                            query = query.order_by(nullslast(direction()))
                        else:
                            query = query.order_by(nullsfirst(direction()))
            else:
                if not search_params.group_by:
                    pks = primary_key_names(model)
                    pk_order = (getattr(model, field).asc() for field in pks)
                    query = query.order_by(*pk_order)

        # Group the query.
        if search_params.group_by:
            for group_by in search_params.group_by:
                field_name = group_by.field
                if '__' in field_name:
                    field_name, field_name_in_relation = field_name.split('__')
                    relation = getattr(model, field_name)
                    relation_model = relation.mapper.class_
                    field = getattr(relation_model, field_name_in_relation)
                else:
                    field = getattr(model, group_by.field)
                query = query.group_by(field)

        # Apply limit and offset to the query.
        if search_params.limit:
            query = query.limit(search_params.limit)
        if search_params.offset:
            query = query.offset(search_params.offset)

        return query


def create_query(session, model, search_params, _ignore_order_by=False):
    """Returns a SQLAlchemy query object on the given `model` where the search
    for the query is defined by `search_params`.

    The returned query matches the set of all instances of `model` which meet
    the parameters of the search given by `search_params`. For more information
    on search parameters, see :ref:`search`.

    `model` is a SQLAlchemy declarative model representing the database model
    to query.

    `search_params` is either a dictionary (as parsed from a JSON request from
    the client, for example) or a :class:`SearchParameters` instance defining
    the parameters of the query (as returned by
    :func:`SearchParameters.from_dictionary`, for example).

    If `_ignore_order_by` is ``True``, no ``order_by`` method will be called on
    the query, regardless of whether the search parameters indicate that there
    should be an ``order_by``. (This is used internally by Flask-Restless to
    work around a limitation in SQLAlchemy.)

    """
    if isinstance(search_params, dict):
        search_params = SearchParameters.from_dictionary(search_params)
    return QueryBuilder.create_query(session, model, search_params,
                                     _ignore_order_by)


def search(session, model, search_params, _ignore_order_by=False):
    """Performs the search specified by the given parameters on the model
    specified in the constructor of this class.

    This function essentially calls :func:`create_query` to create a query
    which matches the set of all instances of ``model`` which meet the search
    parameters defined in ``search_params``, then returns all results (or just
    one if ``search_params['single'] == True``).

    This function returns a single instance of the model matching the search
    parameters if ``search_params['single']`` is ``True``, or a list of all
    such instances otherwise. If ``search_params['single']`` is ``True``, then
    this method will raise :exc:`sqlalchemy.orm.exc.NoResultFound` if no
    results are found and :exc:`sqlalchemy.orm.exc.MultipleResultsFound` if
    multiple results are found.

    `model` is a SQLAlchemy declarative model class representing the database
    model to query.

    `search_params` is a dictionary containing all available search
    parameters. For more information on available search parameters, see
    :ref:`search`. Implementation note: this dictionary will be converted to a
    :class:`SearchParameters` object when the :func:`create_query` function is
    called.

    If `_ignore_order_by` is ``True``, no ``order_by`` method will be called on
    the query, regardless of whether the search parameters indicate that there
    should be an ``order_by``. (This is used internally by Flask-Restless to
    work around a limitation in SQLAlchemy.)

    """
    # `is_single` is True when 'single' is a key in ``search_params`` and its
    # corresponding value is anything except those values which evaluate to
    # False (False, 0, the empty string, the empty list, etc.).
    is_single = search_params.get('single')
    query = create_query(session, model, search_params, _ignore_order_by)
    if is_single:
        # may raise NoResultFound or MultipleResultsFound
        return query.one()
    reset_bind_counter()
    return query
