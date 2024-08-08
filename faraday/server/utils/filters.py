"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import datetime
import logging
import numbers
import typing
from collections.abc import Iterable
from distutils.util import strtobool

# Related third party imports
import marshmallow_sqlalchemy
from dateutil.parser import parse
from marshmallow import Schema, fields, ValidationError, types, validate, post_load
from marshmallow_sqlalchemy.convert import ModelConverter

# Local application imports
from faraday.server.models import (
    VulnerabilityWeb,
    Host,
    Service,
    VulnerabilityTemplate,
    Workspace,
    User,
    CustomFieldsSchema,
)
from faraday.server.utils.search import OPERATORS

VALID_OPERATORS = set(OPERATORS.keys()) - {'desc', 'asc'}
DATETIME_FORMAT = '%Y-%m-%dT%H:%M:%S.%f%z'

logger = logging.getLogger(__name__)


def generate_datetime_filter(filter_: dict = "") -> typing.List:
    """
    Add time to filter['val'] date
    Return a new filter with time added. In case of `eq` or `==` operator will return a range of datetime objects.
    """
    if filter_['op'].lower() in ['>', 'gt', '<=', 'lte']:
        filter_['val'] = (parse(filter_['val']) + datetime.timedelta(hours=23,
                                                                     minutes=59,
                                                                     seconds=59)).strftime(DATETIME_FORMAT)
    elif filter_['op'].lower() in ['==', 'eq']:
        end_date = parse(filter_['val']) + datetime.timedelta(hours=23, minutes=59, seconds=59)
        return [
            {'name': filter_['name'], 'op': '>=', 'val': parse(filter_['val']).strftime(DATETIME_FORMAT)},
            {'name': filter_['name'], 'op': '<=', 'val': end_date.strftime(DATETIME_FORMAT)},
        ]
    elif filter_['op'].lower() in ['>=', 'gte', '<', 'lt']:
        filter_['val'] = parse(filter_['val']).isoformat()

    return [filter_]


class FlaskRestlessFilterSchema(Schema):
    name = fields.String(required=True)
    val = fields.Raw(required=True)
    op = fields.String(validate=validate.OneOf(list(OPERATORS.keys())), required=True)
    valid_relationship = {
        'host': Host,
        'services': Service,
        'workspaces': Workspace
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
            res = self._validate_filter_types(data)
        else:
            res = []
            for filter_ in data:
                res += self._validate_filter_types(filter_)
        return res

    def _model_class(self):
        raise NotImplementedError

    def _validate_filter_types(self, filter_):
        """
            Compares the filter_ list against the model field and the value to be compared.
            PostgreSQL is very strict with types.
            Return a list of filters (filters are dicts)
        """

        if '->' in filter_['name']:
            key = filter_['name'].split('->')[1]
            try:
                custom_field = CustomFieldsSchema.query.filter(CustomFieldsSchema.field_name == key).first()
                if custom_field.field_type == 'date':
                    return [filter_]
            except AttributeError as e:
                raise AttributeError("Invalid filters") from e

        if isinstance(filter_['val'], str) and '\x00' in filter_['val']:
            raise ValidationError('Value can\'t contain null chars')
        if isinstance(filter_['val'], str) and filter_['name'] != 'target':
            if filter_['val'].isnumeric():
                filter_['val'] = int(filter_['val'])
            else:
                try:
                    float_value = float(filter_['val'])
                    filter_['val'] = float_value
                except ValueError:
                    pass
        converter = ModelConverter()
        column_name = filter_['name']
        if '__' in column_name:
            # relation attribute search, example service__port:80
            model_name, column_name = column_name.split('__')
            model = self.valid_relationship.get(model_name, None)
            if not model:
                raise ValidationError('Invalid Relationship')
            column = getattr(model, column_name)
        else:
            try:
                column = getattr(self._model_class(), column_name.split('->')[0])
            except AttributeError as e:
                raise ValidationError('Field does not exists') from e

        if not getattr(column, 'type', None) and filter_['op'].lower():
            if filter_['op'].lower() in ['eq', '==']:
                if filter_['name'] in ['creator', 'hostnames']:
                    # make sure that creator and hostname are compared against a string
                    if not isinstance(filter_['val'], str):
                        raise ValidationError('Relationship attribute to compare to must be a string')
                    return [filter_]
            # has and any should be used with fields that has a relationship with other table
            if filter_['op'].lower() in ['has', 'any', 'not_any']:
                return [filter_]
            else:
                raise ValidationError('Field does not support in operator')

        if filter_['op'].lower() in ['in', 'not_in']:
            # in and not_in must be used with Iterable
            if not isinstance(filter_['val'], Iterable):
                filter_['val'] = [filter_['val']]

        try:
            field = converter.column2field(column)
        except AttributeError as e:
            logger.warning(f"Column {column_name} could not be converted. {e}")
            return [filter_]
        except marshmallow_sqlalchemy.exceptions.ModelConversionError as e:
            logger.warning(f"Column {column_name} could not be converted. {e}")
            return [filter_]

        # Dates
        if isinstance(field, (fields.Date, fields.DateTime)):
            try:
                datetime.datetime.strptime(filter_['val'], '%Y-%m-%d')
                return generate_datetime_filter(filter_)
            except ValueError as e:
                raise ValidationError('Invalid date format. Dates should be in "%Y-%m-%d" format') from e

        if filter_['op'].lower() in ['ilike', 'like']:
            # like must be used with string
            if isinstance(filter_['val'], numbers.Number) or isinstance(field, fields.Number):
                raise ValidationError('Can\'t perform ilike/like against numbers')
            if isinstance(field, fields.Boolean):
                raise ValidationError('Can\'t perform ilike/like against boolean type column')

        if filter_['op'].lower() in ['<', '>', '>=', '<=', 'ge', 'geq', 'lt']:
            # we check that operators can be only used against date or numbers
            if not isinstance(filter_['val'], numbers.Number):
                raise ValidationError('Operators <,> can be used only with numbers or dates')

            if not isinstance(field, (fields.Date, fields.DateTime, fields.Number)):
                if '->' not in column_name:
                    raise ValidationError('Using comparison operator against a field that does not supports it')

        # if the field is boolean, the value must be valid otherwise postgresql will raise an error
        if isinstance(field, fields.Boolean) and not isinstance(filter_['val'], bool):
            try:
                strtobool(filter_['val'])
            except (AttributeError, ValueError) as e:
                raise ValidationError('Can\'t compare Boolean field against a'
                                      ' non boolean value. Please use True or False') from e
        # we try to deserialize the value, any error means that the value was not valid for the field typ3
        # previous checks were added since postgresql is very strict with operators.
        try:
            if isinstance(field, fields.String):
                filter_['val'] = str(filter_['val'])
            else:
                field.deserialize(filter_['val'])
        except TypeError as e:
            raise ValidationError('Invalid value type') from e

        return [filter_]


class FlaskRestlessVulnerabilityFilterSchema(FlaskRestlessFilterSchema):
    def _model_class(self):
        return VulnerabilityWeb


class FlaskRestlessVulnerabilityTemplateFilterSchema(FlaskRestlessFilterSchema):
    def _model_class(self):
        return VulnerabilityTemplate


class FlaskRestlessHostFilterSchema(FlaskRestlessFilterSchema):
    def _model_class(self):
        return Host


class FlaskRestlessWorkspaceFilterSchema(FlaskRestlessFilterSchema):
    def _model_class(self):
        return Workspace


class FlaskRestlessUserFilterSchema(FlaskRestlessFilterSchema):
    def _model_class(self):
        return User


class FlaskRestlessOperator(Schema):
    _or = fields.Nested("self", attribute='or', data_key='or')
    _and = fields.Nested("self", attribute='and', data_key='and')

    model_filter_schemas = [
        FlaskRestlessHostFilterSchema,
        FlaskRestlessVulnerabilityFilterSchema,
        FlaskRestlessWorkspaceFilterSchema,
        FlaskRestlessUserFilterSchema,
        FlaskRestlessVulnerabilityTemplateFilterSchema,
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
        if not isinstance(data, list):
            data = [data]

        res = []
        # the next iteration is required for allow polymorphism in the list of filters
        for search_filter in data:
            # we try to validate against filter schema since the list could contain
            # operators mixed with filters in the list
            valid_count = 0
            for schema in self.model_filter_schemas:
                try:
                    res += schema(many=False).load(search_filter)
                    valid_count += 1
                    break
                except ValidationError:
                    continue

            if valid_count == 0:
                res.append(self._do_load(
                    search_filter, many=False, partial=partial, unknown=unknown, postprocess=True
                ))

        return res


class FlaskRestlessGroupFieldSchema(Schema):
    field = fields.String(required=True)


class FlaskRestlessOrderFieldSchema(Schema):
    field = fields.String(required=True)
    direction = fields.String(validate=validate.OneOf(["asc", "desc"]), required=False)


class FilterSchema(Schema):
    filters = fields.Nested("FlaskRestlessSchema")
    order_by = fields.List(fields.Nested(FlaskRestlessOrderFieldSchema))
    group_by = fields.List(fields.Nested(FlaskRestlessGroupFieldSchema))
    limit = fields.Integer()
    offset = fields.Integer()

    @post_load
    def validate_order_and_group_by(self, data, **kwargs):
        """
            We need to validate that if group_by is used, all the field
            in the order_by must be in group_by fields.
            When using different order_by fields that are not in group by will cause
            an error on PostgreSQL
        """
        if 'group_by' in data and 'order_by' in data:
            group_by_fields = {group_field['field'] for group_field in data['group_by']}
            order_by_fields = {order_field['field'] for order_field in data['order_by']}
            if not order_by_fields.issubset(group_by_fields):
                logger.error(f'All order fields ({order_by_fields}) must be in group by {group_by_fields}.')
                raise ValidationError(f'All order fields ({order_by_fields}) must be in group by {group_by_fields}.')
        return data


class FlaskRestlessSchema(Schema):
    valid_schemas = [
        FilterSchema,
        FlaskRestlessOperator,
        FlaskRestlessVulnerabilityFilterSchema,
        FlaskRestlessVulnerabilityTemplateFilterSchema,
        FlaskRestlessHostFilterSchema,
        FlaskRestlessWorkspaceFilterSchema,
        FlaskRestlessUserFilterSchema,
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
        raise ValidationError(f'No valid schema found. data {data}')
