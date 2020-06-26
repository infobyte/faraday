"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""
import typing
from marshmallow import Schema, fields, ValidationError, types, validate

from faraday.server.models import VulnerabilityWeb
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

VULNERABILITY_FIELDS = [col.name for col in VulnerabilityWeb.__table__.columns] + WHITE_LIST + COUNT_FIELDS


class FlaskRestlessFilterSchema(Schema):
    name = fields.String(validate=validate.OneOf(VULNERABILITY_FIELDS), required=True)
    val = fields.Raw(required=True)
    op = fields.String(validate=validate.OneOf(list(OPERATORS.keys())), required=True)


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
