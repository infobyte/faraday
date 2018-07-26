'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import datetime
from marshmallow import fields, Schema
from marshmallow.exceptions import ValidationError
from dateutil.tz import tzutc

from server.models import VulnerabilityABC


class JSTimestampField(fields.Integer):
    """A field to serialize datetime objects into javascript
    compatible timestamps (like time.time()) * 1000"""

    def _serialize(self, value, attr, obj):
        if value is not None:
            return int(time.mktime(value.timetuple()) * 1000)

    def _deserialize(self, value, attr, data):
        if value is not None and value:
            return datetime.datetime.fromtimestamp(self._validated(value)/1e3)


class PrimaryKeyRelatedField(fields.Field):
    def __init__(self, field_name='id', *args, **kwargs):
        self.field_name = field_name
        self.many = kwargs.get('many', False)
        super(PrimaryKeyRelatedField, self).__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj):
        if self.many:
            ret = []
            for item in value:
                ret.append(getattr(item, self.field_name))
            return ret
        else:
            if value is None:
                return None
            return getattr(value, self.field_name)

    def _deserialize(self, value, attr, data):
        raise NotImplementedError("Only dump is implemented for now")


class SelfNestedField(fields.Field):
    """A field to make namespaced schemas. It allows to have
    a field whose contents are the dump of the same object with
    other schema"""

    # Required because the target attribute will probably not exist
    _CHECK_ATTRIBUTE = False

    def __init__(self, target_schema, *args, **kwargs):
        self.target_schema = target_schema
        super(SelfNestedField, self).__init__(*args, **kwargs)

    def _serialize(self, value, attr, obj):
        ret, errors = self.target_schema.dump(obj)
        if errors:
            raise ValidationError(errors, data=ret)
        return ret

    def _deserialize(self, value, attr, data):
        """
        It would be awesome if this method could also flatten the dict keys into the parent
        """
        load = self.target_schema.load(value)
        if load.errors:
            raise ValidationError(load.errors)

        return load.data


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

        super(MutableField, self).__init__(**kwargs)

    def _serialize(self, value, attr, obj):
        return self.read_field._serialize(value, attr, obj)

    def _deserialize(self, value, attr, data):
        return self.write_field._deserialize(value, attr, data)

    def _add_to_schema(self, field_name, schema):
        # Propagate to child fields
        super(MutableField, self)._add_to_schema(field_name, schema)
        self.read_field._add_to_schema(field_name, schema)
        self.write_field._add_to_schema(field_name, schema)


class SeverityField(fields.String):
    """
    Custom field for the severity, with the proper mappings to make
    it compatible with the web UI
    """

    def _serialize(self, value, attr, obj):
        ret = super(SeverityField, self)._serialize(value, attr, obj)
        if ret == 'medium':
            return 'med'
        elif ret == 'informational':
            return 'info'
        return ret

    def _deserialize(self, value, attr, data):
        ret = super(SeverityField, self)._serialize(value, attr, data)
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
        super(NullToBlankString, self).__init__(*args, **kwargs)
        # Always make the field nullable because it is translated
        self.allow_none = True
        self.default = ''

    def deserialize(self, value, attr=None, data=None):
        # Validate required fields, deserialize, then validate
        # deserialized value
        if value:
            value = value.replace('\0',
                              '')  # Postgres does not allow nul 0x00 in the strings.
        self._validate_missing(value)
        if getattr(self, 'allow_none', False) is True and value is None:
            return ''
        output = self._deserialize(value, attr, data)
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


class StrictDateTimeField(fields.DateTime):
    """
    Marshmallow DateTime field with extra parameter to control
    whether dates should be loaded as tz_aware or not
    """
    # Taken from
    # https://github.com/Nobatek/umongo/blob/14ec7e40ca517071d9374af39f8409223e097253/umongo/marshmallow_bonus.py

    # TODO migration: write me some tests!!!

    def __init__(self, load_as_tz_aware=False, *args, **kwargs):
        super(StrictDateTimeField, self).__init__(*args, **kwargs)
        self.load_as_tz_aware = load_as_tz_aware

    def _deserialize(self, value, attr, data):
        if isinstance(value, datetime.datetime):
            date = value
        else:
            date = super(StrictDateTimeField, self)._deserialize(value, attr, data)
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
