from faraday.server.commands.app_urls import openapi_format


def test_openapi_format(session):
    openapi_format("http://localhost")
