"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import datetime
import json
import logging
import time

# Related third party imports
from dateutil.tz import tzutc
from flask import g
from marshmallow import fields, Schema, post_dump, EXCLUDE
from marshmallow.utils import missing as missing_
from marshmallow.exceptions import ValidationError

from faraday.server.models import (
    db,
    VulnerabilityABC,
    CustomFieldsSchema,
)

logger = logging.getLogger(__name__)


def validate_date_string(date):
    """
    Validate date string for custom_fields where field_type is date, intended: YYYY-MM-DD
    """
    try:
        datetime.datetime.strptime(date, "%Y-%m-%d")
        return True
    except ValidationError:
        return False


class JSTimestampField(fields.Integer):
    """A field to serialize datetime objects into javascript
    compatible timestamps (like time.time()) * 1000"""

    def _serialize(self, value, attr, obj):
        if value is not None:
            return int(time.mktime(value.timetuple()) * 1000)

    def _deserialize(self, value, attr, data, **kwargs):
        if value is not None and value:
            return datetime.datetime.fromtimestamp(self._validated(value) / 1e3)


class FaradayCustomField(fields.Field):
    def __init__(self, table_name='vulnerability', *args, **kwargs):
        self.table_name = table_name
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj, **kwargs):
        if not value:
            value = {}
        res = {}

        try:
            custom_fields = g.custom_fields[self.table_name]
        except KeyError:
            custom_fields = db.session.query(CustomFieldsSchema).filter_by(
                    table_name=self.table_name).all()
            g.custom_fields[self.table_name] = custom_fields
        except AttributeError:
            custom_fields = db.session.query(CustomFieldsSchema).filter_by(
                table_name=self.table_name).all()

        for custom_field in custom_fields:
            serialized_value = value.get(custom_field.field_name)
            if type(serialized_value) is list:
                res[custom_field.field_name] = [element['value'] if type(element) is dict
                                                else element for element in serialized_value]
            else:
                res[custom_field.field_name] = serialized_value

        return res

    def _deserialize(self, value, attr, data, **kwargs):
        serialized = {}
        if value is not None and value:
            for key, raw_data in value.items():
                if not raw_data:
                    continue
                field_schema = db.session.query(CustomFieldsSchema).filter_by(
                    table_name=self.table_name,
                    field_name=key,
                ).first()
                if not field_schema:
                    logger.warning(
                        f"Invalid custom field {key}. Did you forget to add it?"
                    )
                    continue
                if field_schema.field_type == 'str':
                    serialized[key] = str(raw_data)
                elif field_schema.field_type == 'int':
                    try:
                        serialized[key] = int(raw_data)
                    except TypeError:
                        return None
                    except ValueError as e:
                        raise ValidationError("Can not convert custom type to int") from e
                elif field_schema.field_type == 'list':
                    serialized[key] = raw_data
                elif field_schema.field_type == 'choice':
                    serialized[key] = str(raw_data)
                elif field_schema.field_type == 'date':
                    raw_data = str(raw_data).replace('/', '-')
                    if validate_date_string(raw_data):
                        serialized[key] = raw_data
                    else:
                        raise ValidationError("The value is not a valid date")
                else:
                    raise ValidationError("Custom Field datatype not supported yet")

        return serialized


class PrimaryKeyRelatedField(fields.Field):
    def __init__(self, field_name='id', *args, **kwargs):
        self.field_name = field_name
        self.many = kwargs.get('many', False)
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj):
        if self.many:
            ret = []
            for item in value:
                try:
                    ret.append(getattr(item, self.field_name))
                except AttributeError:
                    ret.append(item[self.field_name])
            return ret
        else:
            if value is None:
                return None
            return getattr(value, self.field_name)

    def _deserialize(self, value, attr, data, **kwargs):
        raise NotImplementedError("Only dump is implemented for now")


class SelfNestedField(fields.Field):
    """A field to make namespaced schemas. It allows to have
    a field whose contents are the dump of the same object with
    other schema"""

    # Required because the target attribute will probably not exist
    _CHECK_ATTRIBUTE = False

    def __init__(self, target_schema, *args, **kwargs):
        self.target_schema = target_schema
        super().__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj):
        return self.target_schema.dump(obj)

    def _deserialize(self, value, attr, data, **kwargs):
        """
        It would be awesome if this method could also flatten the dict keys into the parent
        """
        return self.target_schema.load(value)


class MutableField(fields.Field):
    """
    A field that enables the use of different fields for read and write.

    This is useful in many cases, like for example when you want to use a
    Nested field to show the data but an Integer field (that uses to be a
    primary key) for writing/deserializing.
    """

    # TODO: inherit required and other properties from the child fields

    def __init__(self, read_field, write_field, **kwargs):
        self.read_field = read_field
        self.write_field = write_field

        # Set _CHECK_ATTRIBUTE based on the read field because it is used
        # during serialization
        self._CHECK_ATTRIBUTE = self.read_field._CHECK_ATTRIBUTE

        # Propagate required=True to the children fields
        if kwargs.get('required'):
            self.read_field.required = self.write_field.required = True

        super().__init__(**kwargs)

    def _serialize(self, value, attr, obj):

        # TODO: see root cause of the bug that required this line to be added
        self.read_field.parent = self.parent

        return self.read_field._serialize(value, attr, obj)

    def _deserialize(self, value, attr, data, **kwargs):

        # TODO: see root cause of the bug that required this line to be added
        self.write_field.parent = self.parent

        return self.write_field._deserialize(value, attr, data, **kwargs)

    def _bind_to_schema(self, field_name, schema):
        # Propagate to child fields
        super()._bind_to_schema(field_name, schema)
        self.read_field._bind_to_schema(field_name, schema)
        self.write_field._bind_to_schema(field_name, schema)


class SeverityField(fields.String):
    """
    Custom field for the severity, with the proper mappings to make
    it compatible with the web UI
    """

    def _serialize(self, value, attr, obj):
        ret = super()._serialize(value, attr, obj)
        if ret == 'medium':
            return 'med'
        elif ret == 'informational':
            return 'info'
        return ret

    def _deserialize(self, value, attr, data, **kwargs):
        ret = super()._serialize(value, attr, data)
        if ret == 'med':
            return 'medium'
        elif ret == 'info':
            return 'informational'
        if ret not in VulnerabilityABC.SEVERITIES:
            raise ValidationError("Invalid severity type.")
        return ret


class NullToBlankString(fields.String):
    """
    Custom field that converts null into an empty value. Created for
    compatibility with the web ui.

    Cleans null 0x00 in the string to avoid postgresql bug.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Always make the field nullable because it is translated
        self.allow_none = True
        self.default = ''

    def deserialize(self, value, attr=None, data=None, **kwargs):
        # Validate required fields, deserialize, then validate
        # deserialized value
        self._validate_missing(value)
        if value is missing_:
            _miss = self.missing
            return _miss() if callable(_miss) else _miss
        if isinstance(value, str):
            value = value.replace('\0', '')  # Postgres does not allow nul 0x00 in the strings.
        elif value is not None:
            raise ValidationError("Deserializing a non string field when expected")
        if getattr(self, 'allow_none', False) is True and value is None:
            return ''
        output = self._deserialize(value, attr, data, **kwargs)
        self._validate(output)
        return output


class MetadataSchema(Schema):
    command_id = fields.Function(lambda x: None, dump_only=True)

    creator = fields.Function(lambda x: '', dump_only=True)
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='creator')

    update_time = fields.DateTime(attribute='update_date', dump_only=True)
    create_time = fields.DateTime(attribute='create_date', dump_only=True)

    update_user = fields.String(default='', dump_only=True)
    update_action = fields.Integer(default=0, dump_only=True)
    update_controller_action = fields.String(default='', dump_only=True)

    class Meta:
        unknown = EXCLUDE


class StrictDateTimeField(fields.DateTime):
    """
    Marshmallow DateTime field with extra parameter to control
    whether dates should be loaded as tz_aware or not
    """
    # Taken from
    # https://github.com/Nobatek/umongo/blob/14ec7e40ca517071d9374af39f8409223e097253/umongo/marshmallow_bonus.py

    # TODO migration: write me some tests!!!

    def __init__(self, load_as_tz_aware=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.load_as_tz_aware = load_as_tz_aware

    def _deserialize(self, value, attr, data, **kwargs):
        if isinstance(value, datetime.datetime):
            date = value
        else:
            date = super()._deserialize(value, attr, data)
        if self.load_as_tz_aware:
            # If datetime is TZ naive, set UTC timezone
            if date.tzinfo is None or date.tzinfo.utcoffset(date) is None:
                date = date.replace(tzinfo=tzutc())
        else:
            # If datetime is TZ aware, convert it to UTC and remove TZ info
            if date.tzinfo is not None and date.tzinfo.utcoffset(date) is not None:
                date.astimezone(tzutc())
            date = date.replace(tzinfo=None)
        return date


class WorkerActionSchema(Schema):
    action = fields.Method('get_command')

    @staticmethod
    def get_command(obj):
        if obj.command == 'UPDATE':
            return f"--{obj.command}:{obj.field}={obj.value}"
        if obj.command in ['DELETE', 'REMOVE']:
            return "--DELETE:"
        if obj.command == 'ALERT':
            return f"--{obj.command}:{obj.value}"

        raise ValidationError(f"Command {obj.command} not supported.")


class WorkerConditionSchema(Schema):
    condition = fields.Method('get_condition')

    @staticmethod
    def get_condition(obj):
        if obj.operator == "equals":
            operator = "="
        else:
            raise ValidationError(f"Condition operator {obj.operator} not support.")
        return f'{obj.field}{operator}{obj.value}'


class WorkerRuleSchema(Schema):
    id = fields.Integer()
    model = fields.String()
    object = fields.Method('get_object')
    actions = fields.Nested(WorkerActionSchema, attribute='actions', many=True)
    conditions = fields.Nested(WorkerConditionSchema, attribute='conditions', many=True)
    parent = fields.String(allow_none=False, attribute='object_parent')
    disabled = fields.Boolean(allow_none=True, attribute='disabled')
    fields = fields.String(allow_none=False)

    @staticmethod
    def get_object(rule):
        try:
            object_rules = json.loads(rule.object)
        except ValueError:
            rule_name, value = rule.object.split('=')
            object_rules = [{rule_name: value}]

        for object_rule in object_rules:
            for object_rule_name, value in object_rule.items():
                if value == 'informational':
                    value = 'info'
                if value == 'medium':
                    value = 'med'
                return f'{object_rule_name}={value}'

    @post_dump
    def remove_none_values(self, data, **kwargs):
        actions = []
        conditions = []
        for action in data['actions']:
            actions.append(action['action'])
        for condition in data['conditions']:
            conditions.append(condition['condition'])

        data['actions'] = actions
        data['conditions'] = conditions

        return {
            key: value for key, value in data.items()
            if value
        }
