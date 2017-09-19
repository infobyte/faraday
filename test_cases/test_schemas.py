from collections import namedtuple
from marshmallow import Schema, fields
from server.schemas import SelfNestedField

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
