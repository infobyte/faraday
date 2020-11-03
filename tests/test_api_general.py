import re
from faraday.server.web import app

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
    for rule in app.url_map.iter_rules():
        if 'OPTIONS' in rule.methods:
            res = test_client.options(replace_placeholders(rule.rule))
            assert res.status_code == 200, rule.rule
