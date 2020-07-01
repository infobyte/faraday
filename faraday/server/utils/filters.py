"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import typing
import numbers
import datetime

from dateutil.parser import parse
from sqlalchemy import inspect
from collections.abc import Iterable
from dateutil.parser._parser import ParserError
from marshmallow import Schema, fields, ValidationError, types, validate
from marshmallow_sqlalchemy.schema import ModelConverter

from faraday.server.models import VulnerabilityWeb, Host, Service
from faraday.server.utils.search import OPERATORS

WHITE_LIST = [
    'tags__name',
    'service__name',
    'type',
    'policy_violations__name',
    'host__os',
    'references__name',
    'evidence__filename',
    'service__port',
    'hostnames',
    'creator'
]


COUNT_FIELDS = [
    'host__vulnerability_critical_generic_count',
    'host__vulnerability_high_generic_count',
    'host__vulnerability_medium_generic_count',
    'host__vulnerability_low_generic_count',
    'host__vulnerability_info_generic_count',
]

VULNERABILITY_FIELDS = [str(algo).split('.')[1] for algo in inspect(VulnerabilityWeb).attrs] + WHITE_LIST + COUNT_FIELDS


VALID_OPERATORS = set(OPERATORS.keys()) - set(['desc', 'asc'])


class FlaskRestlessFilterSchema(Schema):
    name = fields.String(validate=validate.OneOf(VULNERABILITY_FIELDS), required=True)
    val = fields.Raw(required=True)
    op = fields.String(validate=validate.OneOf(list(OPERATORS.keys())), required=True)
    valid_relationship = {
        'host': Host,
        'service': Service
    }

    def load(
        self,
        data: typing.Union[
            typing.Mapping[str, typing.Any],
            typing.Iterable[typing.Mapping[str, typing.Any]],
        ],
        *,
        many: bool = None,
        partial: typing.Union[bool, types.StrSequenceOrSet] = None,
        unknown: str = None
    ):
        data = super().load(data, many=many, partial=partial, unknown=unknown)
        if not isinstance(data, list):
            self._validate_filter_types(data)
        else:
            for filter_ in data:
                self._validate_filter_types(filter_)
        return data

    def _validate_filter_types(self, filter_):
        converter = ModelConverter()
        column_name = filter_['name']
        if '__' in column_name:
            model_name, column_name = column_name.split('__')
            model = self.valid_relationship.get(model_name, None)
            if not model:
                raise ValidationError('Invalid Relationship')
            column = getattr(model, column_name)
        else:
            column = getattr(VulnerabilityWeb, column_name)
        if not getattr(column, 'type', None) and filter_['op'].lower():
            if filter_['op'].lower() in ['eq', '==']:
                if filter_['name'] in ['creator', 'hostnames']:
                    return
            else:
                raise ValidationError('Field does not support in operator')

        if filter_['op'].lower() in ['in', 'not_in']:
            if not isinstance(filter_['val'], Iterable):
                filter_['val'] = [filter_['val']]

        if filter_['op'].lower() in ['ilike', 'like'] and isinstance(filter_['val'], numbers.Number):
            raise ValidationError('Can\'t perfom ilike/like against numbers')

        valid_date = False
        try:
            valid_date = isinstance(parse(filter_['val']), datetime.datetime)
        except (ParserError, TypeError):
            valid_date = False

        if filter_['op'].lower() in ['<', '>']:
           if not valid_date and not isinstance(filter_['val'], numbers.Number):
                raise ValidationError('Operators <,> can be used only with numbers or dates')

        field = converter.column2field(column)
        if isinstance(field, (fields.Date, fields.DateTime)) and valid_date:
            return

        try:
            field.deserialize(filter_['val'])
        except TypeError:
            raise ValidationError('Invalid value type')


class FlaskRestlessOperator(Schema):
    _or = fields.List(fields.Nested("self"), attribute='or', data_key='or')
    _and = fields.List(fields.Nested("self"), attribute='and', data_key='and')

    def load(
        self,
        data: typing.Union[
            typing.Mapping[str, typing.Any],
            typing.Iterable[typing.Mapping[str, typing.Any]],
        ],
        *,
        many: bool = None,
        partial: typing.Union[bool, types.StrSequenceOrSet] = None,
        unknown: str = None
    ):
        if not isinstance(data, list):
            data = [data]

        res = []
        # the next iteration is required for allow polymorphism in the list of filters
        for search_filter in data:
            try:
                res.append(FlaskRestlessFilterSchema(many=False).load(search_filter))
            except ValidationError:
                res.append(self._do_load(
                    search_filter, many=False, partial=partial, unknown=unknown, postprocess=True
                ))

        return res


class FlaskRestlessGroupFieldSchema(Schema):
    field = fields.String(validate=validate.OneOf(VULNERABILITY_FIELDS), required=True)


class FlaskRestlessOrderFieldSchema(Schema):
    field = fields.String(validate=validate.OneOf(VULNERABILITY_FIELDS), required=True)
    direction = fields.String(validate=validate.OneOf(["asc", "desc"]), required=False)


class FilterSchema(Schema):
    filters = fields.List(fields.Nested("FlaskRestlessSchema"))
    order_by = fields.List(fields.Nested(FlaskRestlessOrderFieldSchema))
    group_by = fields.List(fields.Nested(FlaskRestlessGroupFieldSchema))
    limit = fields.Integer()
    offset = fields.Integer()


class FlaskRestlessSchema(Schema):
    valid_schemas = [
        FilterSchema,
        FlaskRestlessFilterSchema,
        FlaskRestlessOperator,
    ]

    def load(
        self,
        data: typing.Union[
            typing.Mapping[str, typing.Any],
            typing.Iterable[typing.Mapping[str, typing.Any]],
        ],
        *,
        many: bool = None,
        partial: typing.Union[bool, types.StrSequenceOrSet] = None,
        unknown: str = None
    ):
        many = False
        if isinstance(data, list):
            many = True
        for schema in self.valid_schemas:
            try:
                return schema(many=many).load(data)
            except ValidationError:
                continue
        raise ValidationError('No valid schema found. data {}'.format(data))
