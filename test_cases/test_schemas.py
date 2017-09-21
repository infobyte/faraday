import time
import datetime
from collections import namedtuple
from marshmallow import Schema, fields
from server.schemas import SelfNestedField, JSTimestampField

Place = namedtuple('Place', ['name', 'x', 'y'])


class PointSchema(Schema):
    x = fields.Float()
    y = fields.Float()


class PlaceSchema(Schema):
    name = fields.Str()
    coords = SelfNestedField(PointSchema())


class TestSelfNestedField:
    def test_field_serialization(self):
        point = Place('home', 123, 456.1)
        schema = PlaceSchema()
        dumped = schema.dump(point).data
        assert dumped == {"name": "home", "coords": {"x": 123.0, "y": 456.1}}


class TestJSTimestampField:
    def test_parses_current_datetime(self):
        ts = time.time()
        dt = datetime.datetime.fromtimestamp(ts)
        parsed = JSTimestampField()._serialize(dt, None, None)
        assert parsed == int(ts) * 1000
        assert isinstance(parsed, int)

    def test_parses_null_datetime(self):
        assert JSTimestampField()._serialize(None, None, None) is None
