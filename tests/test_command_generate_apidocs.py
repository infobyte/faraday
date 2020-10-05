from faraday.server.commands.app_urls import openapi_format


def test_changes_password_command(session):
    openapi_format(format="yaml", no_servers=True)
