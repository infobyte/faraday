import pytest

from marshmallow.exceptions import ValidationError

from faraday.server.utils.filters import FilterSchema
from faraday.server.utils.filters import FlaskRestlessSchema


class TestFilters:

    def test_restless_using_group_by(self):
        test_filter = {
            "group_by": [
                {"field": "severity"}
            ]
        }
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_restless_using_order_by(self):
        test_filter = {
            "order_by": [
                {"field": "host__vulnerability_critical_generic_count"},
                {"field": "host__vulnerability_high_generic_count"},
                {"field": "host__vulnerability_medium_generic_count"},
            ],
            "filters": [{
                "or": [
                    {"name": "severity", "op": "==", "val": "critical"},
                    {"name": "severity", "op": "==", "val": "high"},
                    {"name": "severity", "op": "==", "val": "medium"},
                ]
            }]
        }
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_FlaskRestlessSchema_(self):
        test_filter = [{"name": "severity", "op": "eq", "val": "low"}]
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_simple_and_operator(self):
        test_filter = {"filters": [
            {'and': [
                {"name": "severity", "op": "eq", "val": "low"},
                {"name": "severity", "op": "eq", "val": "medium"}
            ]
            }

        ]}
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_equals_by_date(self):
        test_filter = {"filters": [
            {"name": "create_date", "op": "eq", "val": '2020-01-10'}
        ]}
        res = FlaskRestlessSchema().load(test_filter)
        assert res == {"filters": [
            {'name': 'create_date', 'op': '>=', 'val': '2020-01-10T00:00:00.000000'},
            {'name': 'create_date', 'op': '<=', 'val': '2020-01-10T23:59:59.000000'}
        ]}

    def test_simple_or_operator(self):
        test_filter = {"filters": [
            {"or": [
                {"name": "id", "op": "lt", "val": 10},
                {"name": "id", "op": "gt", "val": 20}
            ]}
        ]}
        res = FlaskRestlessSchema().load(test_filter)

        assert res == test_filter

    def test_filters(self):
        _filter = {"filters": [{"name": "severity", "op": "eq", "val": "low"}]}
        assert FlaskRestlessSchema().load(_filter) == _filter

    def test_filters_fail(self):
        _filter = [{"name": "host_id", "op": "eq", "val": 1}]
        assert FlaskRestlessSchema().load(_filter) == _filter

    def test_nested_filters(self):
        _filter = {"filters": [
            {"and": [
                {
                    "or": [
                        {
                            "name": "name",
                            "op": "ilike",
                            "val": "%hola mundo%"
                        },
                        {
                            "name": "name",
                            "op": "ilike",
                            "val": "%prueba%"
                        }
                    ]
                },
                {
                    "name": "severity",
                    "op": "eq",
                    "val": "high"
                }
            ]}
        ]}
        assert FlaskRestlessSchema().load(_filter) == _filter

    def test_nested_filters_fail(self):
        _filter = {"filters": [{
            "and": [
                {
                    "or": [
                        {
                            "name": "test",
                            "op": "ilike",
                            "val": "%hola mundo%"
                        },
                        {
                            "name": "toFail",
                            "op": "ilike",
                            "val": "%prueba%"
                        }
                    ]
                },
                {
                    "name": "severity",
                    "op": "eq",
                    "val": "high"
                }
            ]
        }]}
        with pytest.raises(ValidationError):
            FlaskRestlessSchema().load(_filter)

    def test_full_filters(self):
        _filter = {"filters": [{"name": "severity", "op": "eq", "val": "low"}]}
        assert FlaskRestlessSchema().load(_filter) == _filter

    def test_find_item_function(self):
        _filter = [{"name": "severity", "op": "eq", "val": "low"}]
        assert FlaskRestlessSchema().load(_filter) == _filter

    def test_nested_find_item_function(self):
        _filter = {
            "and": [
                {
                    "or": [
                        {
                            "name": "name",
                            "op": "ilike",
                            "val": "%hola mundo%"
                        },
                        {
                            "name": "description",
                            "op": "ilike",
                            "val": "%prueba%"
                        }
                    ]
                },
                {
                    "name": "severity",
                    "op": "eq",
                    "val": "high"
                }
            ]
        }
        res = FlaskRestlessSchema().load(_filter)[0]
        assert 'and' in res
        for and_op in res['and']:
            if 'or' in and_op:
                for or_op in and_op['or']:
                    if or_op['name'] == 'name':
                        assert or_op == {"name": "name", "op": "ilike", "val": "%hola mundo%"}
                    elif or_op['name'] == 'description':
                        assert or_op == {"name": "description", "op": "ilike", "val": "%prueba%"}
                    else:
                        raise Exception('Invalid result')
            else:
                assert and_op == {"name": "severity", "op": "eq", "val": "high"}

    def test_case_1(self):
        filter_schema = FilterSchema()
        filters = {'filters': [{"name": "confirmed", "op": "==", "val": "true"}]}
        res = filter_schema.load(filters)
        assert res == filters

    def test_case_2(self):
        filter_schema = FilterSchema()
        filters = {'filters': [{'and': [{"name": "confirmed", "op": "==", "val": "true"}]}]}
        res = filter_schema.load(filters)
        assert res == filters

    def test_case_3(self):
        filters = {'filters': [
            {"and": [
                {"and": [
                    {"name": "severity", "op": "eq", "val": "critical"},
                    {"name": "confirmed", "op": "==", "val": "true"}
                ]},
                {"name": "host__os", "op": "has", "val": "Linux"}
            ]}
        ]}
        res = FilterSchema().load(filters)
        assert res == filters

    def test_test_case_recursive(self):
        filters = {"filters":
            [{"or": [
                {"name": "severity", "op": "eq", "val": "medium"},
                {"or": [
                    {"name": "severity", "op": "eq", "val": "high"},
                    {"and": [
                        {"and": [
                            {"name": "severity", "op": "eq", "val": "critical"},
                            {"name": "confirmed", "op": "==", "val": "true"}
                        ]},
                        {"name": "host__os", "op": "has", "val": "Linux"}
                    ]}
                ]}
            ]}
            ]}
        res = FilterSchema().load(filters)
        assert res == filters

    def test_case_recursive_2(self):
        filters = {'filters': [
            {"and": [
                {"and": [
                    {"name": "severity", "op": "eq", "val": "critical"},
                    {"name": "confirmed", "op": "==", "val": "true"}
                ]},
                {"name": "host__os", "op": "has", "val": "Linux"}
            ]}
        ]}

        res = FilterSchema().load(filters)
        assert res == filters

    def test_case_filter_invalid_attr(self):
        filters = {'filters': [
            {"name": "columna_pepe", "op": "has", "val": "Linux"}
        ]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_target_filter_should_not_cast_val_to_int(self):
        filters = {'filters': [{'name': 'target', 'op': '==', 'val': '1'}]}
        res = FilterSchema().load(filters)
        assert isinstance(res["filters"][0]['val'], str)
