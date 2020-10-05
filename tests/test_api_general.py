from faraday.server.web import app


def test_options(test_client):
    for rule in app.url_map.iter_rules():
        if 'OPTIONS' in rule.methods:
            res = test_client.options(rule.rule)
            assert res.status_code == 200, rule.rule
