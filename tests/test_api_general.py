import re
from faraday.server.web import get_app

placeholders = {
    r".*(<int:.*>).*": "1"
}


def replace_placeholders(rule: str):
    for key, value in placeholders.items():
        match = re.match(key, rule)
        if match:
            for placeholder in match.groups():
                rule = rule.replace(placeholder, value)
    return rule


def test_options(test_client):
    for rule in get_app().url_map.iter_rules():
        if 'OPTIONS' in rule.methods:
            res = test_client.options(replace_placeholders(rule.rule))
            assert res.status_code == 200, rule.rule


def test_v3_endpoints():
    rules = list(
        filter(lambda rule: rule.rule.startswith("/v3") and rule.rule.endswith("/"), get_app().url_map.iter_rules())
    )
    assert len(rules) == 0, [rule.rule for rule in rules]


def test_v2_in_v3_endpoints():
    exceptions = {
        '/v3/ws/<workspace_id>/activate',
        '/v3/ws/<workspace_id>/change_readonly',
        '/v3/ws/<workspace_id>/deactivate',
        '/v3/ws/<workspace_name>/hosts/bulk_delete',
        '/v3/ws/<workspace_name>/vulns/bulk_delete',
        '/v3/ws/<workspace_name>/vulns/<int:vuln_id>/attachments'
    }
    rules_v2 = set(
        map(
            lambda rule: rule.rule.replace("v2", "v3").rstrip("/"),
            filter(lambda rule: rule.rule.startswith("/v2"), get_app().url_map.iter_rules())
        )
    )
    rules = set(
        map(lambda rule: rule.rule, filter(lambda rule: rule.rule.startswith("/v3"), get_app().url_map.iter_rules()))
    )
    exceptions_present_v2 = rules_v2.intersection(exceptions)
    assert len(exceptions_present_v2) == len(exceptions), sorted(exceptions_present_v2)
    exceptions_present = rules.intersection(exceptions)
    assert len(exceptions_present) == 0, sorted(exceptions_present)
    # We can have extra endpoints in v3 (like all the PATCHS)
    difference = rules_v2.difference(rules).difference(exceptions)
    assert len(difference) == 0, sorted(difference)
