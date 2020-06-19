from faraday.server.utils.filters import FilterSchema
from faraday.server.utils.filters import is_valid_filter, find_item, FlaskRestlessSchema


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
            "order_by":[
                {"field":"host__vulnerability_critical_generic_count"},
                {"field":"host__vulnerability_high_generic_count"},
                {"field":"host__vulnerability_medium_generic_count"},
            ],
            "filters": [{
                "or": [
                    {"name": "severity", "op": "==", "val": "critical"},
                    {"name": "severity", "op": "==", "val": "high"},
                    {"name": "severity", "op": "==", "val": "med"},
                ]
            }]
        }
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter


    def test_FlaskRestlessSchema_(self):
        test_filter = {"name": "severity", "op": "eq", "val": "low"}
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_simple_and_operator(self):
        test_filter = {"filters": [
            {'and': [
                    {"name": "severity", "op": "eq", "val": "low"},
                    {"name": "severity", "op": "eq", "val": "med"}
                ]
            }

        ]}
        res = FlaskRestlessSchema().load(test_filter)
        assert res == test_filter

    def test_simple_or_operator(self):
        test_filter = {"filters": [
            {"or": [
                {"name": "severity", "op": "lt", "val": 10},
                {"name": "severity", "op": "gt", "val": 20}
            ]}
        ]}
        res = FlaskRestlessSchema().load(test_filter)

        assert res == test_filter

    def test_filters(self):
        _filter = {"filters": [{"name": "severity", "op": "eq", "val": "low"}]}
        assert is_valid_filter(_filter) is True

    def test_filters_fail(self):
        _filter = {"name": "host_id", "op": "eq", "val": "1"}
        assert is_valid_filter(_filter) is False

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
        assert is_valid_filter(_filter) is True

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
        assert is_valid_filter(_filter) is False

    def test_full_filters(self):
        _filter = {"filters": [{"name": "severity", "op": "eq", "val": "low"}]}
        assert is_valid_filter(_filter) is True

    def test_find_item_function(self):
        _filter = {"name": "severity", "op": "eq", "val": "low"}
        assert find_item(_filter) == ['severity']

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
                            "name": "desc",
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
        assert find_item(_filter) == ['name', 'desc', 'severity']

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
"""
{"filters":
[{"or":[
    {"name":"severity","op":"eq","val":"medium"},
    {"or":[
        {"name":"severity","op":"eq","val":"high"},
        {"and":[
            {"and":[
                {"name":"severity","op":"eq","val":"critical"},
                {"name":"confirmed","op":"==","val":"true"}
            ]},
            {"name":"host__os","op":"has","val":"Linux"}
            ]}
        ]}
    ]}
]}
"""

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
print(res)