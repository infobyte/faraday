import pytest

from marshmallow.exceptions import ValidationError

from faraday.server.utils.filters import (
    FilterSchema,
    FlaskRestlessSchema,
    FlaskRestlessUserFilterSchema,
    FlaskRestlessCredentialFilterSchema,
    FlaskRestlessVulnerabilityFilterSchema,
)


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

    def test_range_operator_with_date_values(self):
        """Test range operator with date values"""
        filters = {'filters': [{'name': 'create_date', 'op': 'range', 'val': '2020-01-01,2020-12-31'}]}
        res = FilterSchema().load(filters)
        # The range should be parsed into date objects
        assert len(res["filters"]) == 2
        assert res["filters"][0]['op'] == '>='
        assert res["filters"][1]['op'] == '<='

    def test_range_operator_invalid_format(self):
        """Test range operator with invalid format should raise ValidationError"""
        filters = {'filters': [{'name': 'id', 'op': 'range', 'val': '2'}]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_range_operator_non_numeric_values(self):
        """Test range operator with non-numeric values should raise ValidationError"""
        filters = {'filters': [{'name': 'id', 'op': 'range', 'val': 'abc,def'}]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_range_operator_with_one_date(self):
        """Test range operator with one date value"""
        filters = {'filters': [{'name': 'create_date', 'op': 'range', 'val': '2020-01-01'}]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_range_operator_with_date_on_non_date_name(self):
        """Test range operator with date values"""
        filters = {'filters': [{'name': 'id', 'op': 'range', 'val': '2020-01-01,2020-12-31'}]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_user_password_direct_filter_is_rejected(self):
        with pytest.raises(ValidationError):
            FlaskRestlessUserFilterSchema().load({'name': 'password', 'op': 'like', 'val': '$2b$1%'})

    def test_access_token_direct_filter_is_rejected_on_any_schema(self):
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema().load({'name': 'access_token', 'op': 'eq', 'val': 'abc123'})

    def test_credential_password_direct_filter_is_allowed(self):
        result = FlaskRestlessCredentialFilterSchema().load({'name': 'password', 'op': 'eq', 'val': 'secret'})
        assert result == [{'name': 'password', 'op': 'eq', 'val': 'secret'}]

    def test_credential_access_token_direct_filter_is_rejected(self):
        with pytest.raises(ValidationError):
            FlaskRestlessCredentialFilterSchema().load({'name': 'access_token', 'op': 'eq', 'val': 'abc123'})

    def test_sensitive_field_via_has_relationship_is_rejected(self):
        # {"name":"creator","op":"has","val":{"name":"password","op":"like","val":"$2b$1%"}}
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema().load(
                {'name': 'creator', 'op': 'has', 'val': {'name': 'password', 'op': 'like', 'val': '$2b$1%'}}
            )

    def test_sensitive_field_via_any_relationship_is_rejected(self):
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema().load(
                {'name': 'creator', 'op': 'any', 'val': {'name': 'password', 'op': 'eq', 'val': 'secret'}}
            )

    def test_sensitive_field_deeply_nested_in_and_is_rejected(self):
        filters = {'filters': [
            {'and': [
                {'name': 'severity', 'op': 'eq', 'val': 'high'},
                {'name': 'creator', 'op': 'has', 'val': {'name': 'password', 'op': 'like', 'val': '%secret%'}}
            ]}
        ]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_sensitive_field_deeply_nested_in_or_is_rejected(self):
        filters = {'filters': [
            {'or': [
                {'name': 'confirmed', 'op': '==', 'val': 'true'},
                {'name': 'creator', 'op': 'has', 'val': {'name': 'password', 'op': 'like', 'val': '%secret%'}}
            ]}
        ]}
        with pytest.raises(ValidationError):
            FilterSchema().load(filters)

    def test_sensitive_field_via_double_underscore_notation_is_rejected(self):
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema().load(
                {'name': 'creator__password', 'op': 'like', 'val': '$2b$1%'}
            )

    def test_non_sensitive_field_via_double_underscore_notation_is_allowed(self):
        result = FlaskRestlessVulnerabilityFilterSchema().load(
            {'name': 'creator__name', 'op': 'eq', 'val': 'john'}
        )
        assert result == [{'name': 'creator__name', 'op': 'eq', 'val': 'john'}]

    def test_sensitive_field_compound_name_in_nested_val_is_rejected(self):
        # defense-in-depth: compound name like 'creator__password' inside a nested has/any val
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema().load(
                {'name': 'creator', 'op': 'has', 'val': {'name': 'creator__password', 'op': 'like', 'val': '$2b$1%'}}
            )

    # Regression tests for the Dashboard "Not Closed" filter bug: `in`/`not_in`
    # against a non-fields.String field (e.g. the `status` Enum column, whose
    # converted marshmallow field validates each value with OneOf) used to
    # call `field.deserialize(filter_['val'])` on the *whole list*, which
    # marshmallow rejects as "not one of" the allowed choices. Each element of
    # the list must be validated individually instead.
    def test_in_operator_on_enum_field_with_valid_values(self):
        result = FlaskRestlessVulnerabilityFilterSchema(many=True).load(
            [{'name': 'status', 'op': 'in', 'val': ['open', 're-opened']}]
        )
        assert result[0]['val'] == ['open', 're-opened']

    def test_in_operator_on_enum_field_rejects_invalid_value(self):
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema(many=True).load(
                [{'name': 'status', 'op': 'in', 'val': ['open', 'bogus']}]
            )

    def test_not_in_operator_on_enum_field_with_valid_values(self):
        result = FlaskRestlessVulnerabilityFilterSchema(many=True).load(
            [{'name': 'status', 'op': 'not_in', 'val': ['closed', 'risk-accepted']}]
        )
        assert result[0]['val'] == ['closed', 'risk-accepted']

    def test_in_operator_on_string_field_coerces_each_element(self):
        # Before the fix, str(['a', 'b']) collapsed the whole list into the
        # single, unusable string "['a', 'b']" for fields.String columns.
        result = FlaskRestlessVulnerabilityFilterSchema(many=True).load(
            [{'name': 'name', 'op': 'in', 'val': ['Vuln A', 'Vuln B']}]
        )
        assert result[0]['val'] == ['Vuln A', 'Vuln B']

    def test_in_operator_rejects_scalar_value(self):
        # The front always sends a list for in/not_in; a scalar is now
        # rejected outright instead of being silently wrapped into a list.
        with pytest.raises(ValidationError):
            FlaskRestlessVulnerabilityFilterSchema(many=True).load(
                [{'name': 'status', 'op': 'in', 'val': 'open'}]
            )


class TestSensitiveGroupByAndOrderBy:
    """group_by/order_by are a separate branch of FilterSchema: they never go
    through _validate_filter_types, so _reject_sensitive_field_name is what
    keeps search() from resolving a sensitive column with getattr()."""

    @pytest.mark.parametrize("field", [
        "password",
        "creator__password",
        "token",
        "creator__token",
        "fs_uniquifier",
        "creator__session_id",
        "creator__access_token",
    ])
    def test_group_by_sensitive_field_is_rejected(self, field):
        with pytest.raises(ValidationError):
            FlaskRestlessSchema().load({"filters": [], "group_by": [{"field": field}]})

    @pytest.mark.parametrize("field", ["password", "creator__password", "token"])
    def test_order_by_sensitive_field_is_rejected(self, field):
        with pytest.raises(ValidationError):
            FlaskRestlessSchema().load({"filters": [], "order_by": [{"field": field}]})

    @pytest.mark.parametrize("field", ["name", "severity", "creator__username", "confirmed"])
    def test_group_by_regular_field_is_allowed(self, field):
        res = FlaskRestlessSchema().load({"filters": [], "group_by": [{"field": field}]})
        assert res["group_by"] == [{"field": field}]
