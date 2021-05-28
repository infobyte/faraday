 * ADD `Basic Auth` support
 * ADD support for GET method in websocket_tokens, POST will be deprecated in the future
 * ADD CVSS(String), CWE(String), CVE(relationship) columns to vulnerability model and API
 * ADD agent token's API says the renewal cycling duration
 * MOD Improve database model to be able to delete workspaces fastly
 * MOD Improve code style and uses (less flake8 exceptions, py3 `super` style, Flask app as singleton, etc)
 * MOD workspaces' names regex to verify they cannot contain forward slash (`/`)
 * MOD Improve bulk create logs
 * FIX Own schema breaking Marshmallow 3.11.0+
 * UPD flask_security_too to version 4.0.0+
