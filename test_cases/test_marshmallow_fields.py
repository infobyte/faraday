import time
import datetime
import pytest
from collections import namedtuple
from marshmallow import Schema, fields, ValidationError
from server.schemas import (
    JSTimestampField,
    MutableField,
    PrimaryKeyRelatedField,
    SelfNestedField,
)

Place = namedtuple('Place', ['name', 'x', 'y'])


class PointSchema(Schema):
    x = fields.Float(required=True)
    y = fields.Float(required=True)


class PlaceSchema(Schema):
    name = fields.Str()
    coords = SelfNestedField(PointSchema())


class TestSelfNestedField:

    def load(self, data, schema=PlaceSchema):
        return schema(strict=True).load(data).data

    def test_field_serialization(self):
        point = Place('home', 123, 456.1)
        schema = PlaceSchema()
        dumped = schema.dump(point).data
        assert dumped == {"name": "home", "coords": {"x": 123.0, "y": 456.1}}

    def test_deserialization_success(self):
        load = PlaceSchema().load({"coords": {"x": 123.0, "y": 456.1}}).data
        assert load == {"coords": {"x": 123.0, "y": 456.1}}

    @pytest.mark.parametrize('data', [
        {"coords": {"x": 1}},
        {"coords": {"x": None, "y": 2}},
        {"coords": {"x": "xxx", "y": 2}},
    ])
    def test_deserialization_fails(self, data):
        with pytest.raises(ValidationError):
            self.load(data)


class TestJSTimestampField:
    def test_parses_current_datetime(self):
        ts = time.time()
        dt = datetime.datetime.fromtimestamp(ts)
        parsed = JSTimestampField()._serialize(dt, None, None)
        assert parsed == int(ts) * 1000
        assert isinstance(parsed, int)

    def test_parses_null_datetime(self):
        assert JSTimestampField()._serialize(None, None, None) is None

    def test_deserialization_fails(self):
        ts = time.time()
        dt = datetime.datetime.fromtimestamp(ts)
        loaded = JSTimestampField()._deserialize(ts * 1000,
                                                 None,
                                                 None)
        assert isinstance(loaded, datetime.date)
        assert abs(loaded - dt) < datetime.timedelta(seconds=60)


User = namedtuple('User', ['username', 'blogposts'])
Blogpost = namedtuple('Blogpost', ['id', 'title'])
Profile = namedtuple('Profile', ['user', 'first_name'])


class UserSchema(Schema):
    username = fields.String()
    blogposts = PrimaryKeyRelatedField(many=True)


class ProfileSchema(Schema):
    user = PrimaryKeyRelatedField('username')
    first_name = fields.String()


class TestPrimaryKeyRelatedField:
    @pytest.fixture(autouse=True)
    def load_data(self):
        self.blogposts = [
            Blogpost(1, 'aaa'),
            Blogpost(2, 'bbb'),
            Blogpost(3, 'ccc'),
        ]
        self.user = User('test', self.blogposts)
        self.profile = Profile(self.user, 'david')

    def serialize(self, obj=None, schema=UserSchema):
        return schema(strict=True).dump(obj or self.user).data

    def test_many_id(self):
        assert self.serialize() == {"username": "test",
                                    "blogposts": [1, 2, 3]}

    def test_many_title(self):
        class UserSchemaWithTitle(UserSchema):
            blogposts = PrimaryKeyRelatedField('title', many=True)
        data = self.serialize(schema=UserSchemaWithTitle)
        assert data == {"username": "test", "blogposts": ['aaa', 'bbb', 'ccc']}

    def test_single(self):
        assert self.serialize(self.profile, ProfileSchema) == {
            "user": "test",
            "first_name": "david"
        }

    def test_single_with_none_value(self):
        assert self.serialize(Profile(None, 'other'), ProfileSchema) == {
            "user": None,
            "first_name": "other"
        }

    def test_deserialization_fails(self):
        with pytest.raises(NotImplementedError):
            UserSchema().load({"username": "test",
                               "blogposts": [1, 2, 3]})


Blogpost2 = namedtuple('Blogpost', ['id', 'title', 'user'])


class Blogpost2Schema(Schema):
    id = fields.Integer()
    title = fields.String()
    user = MutableField(fields.Nested(UserSchema, only=('username',)),
                        fields.String())


class TestMutableField:

    serialized_data = {"id": 1, "title": "test", "user": {"username": "john"}}
    loaded_data = {"id": 1, "title": "test", "user": "john"}

    @pytest.fixture(autouse=True)
    def load_data(self):
        self.user = User('john', [])  # I don't care for the user's blogposts
        self.blogpost = Blogpost2(1, 'test', self.user)

    def serialize(self, obj=None, schema=Blogpost2Schema):
        return schema(strict=True).dump(obj or self.blogpost).data

    def load(self, data, schema=Blogpost2Schema):
        return schema(strict=True).load(data).data

    def test_serialize(self):
        assert self.serialize() == self.serialized_data

    def test_deserialize(self):
        assert self.load(self.loaded_data) == self.loaded_data

    def test_deserialize_fails(self):
        with pytest.raises(ValidationError):
            self.load(self.serialized_data)

    def test_required_propagation(self):
        read_field = fields.String()
        write_field = fields.Float()
        mutable = MutableField(read_field, write_field, required=True)
        assert mutable.required
        assert read_field.required
        assert write_field.required

    def test_load_method_field(self):
        class PlaceSchema(Schema):
            name = fields.String()
            x = MutableField(fields.Method('get_x'),
                             fields.String)

            def get_x(self, obj):
                return 5
        assert self.serialize(Place('test', 1, 1), PlaceSchema) == {
            "name": "test",
            "x": 5,
        }
