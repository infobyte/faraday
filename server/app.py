# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import sys
from ConfigParser import NoOptionError

from flask import Flask
from flask.json import JSONEncoder

import server.config
from server.utils.logger import LOGGING_HANDLERS


def create_app(config_filename=None):
    app = Flask(__name__)
    app.debug = server.config.is_debug_mode()
    minify_json_output(app)

    for handler in LOGGING_HANDLERS:
        app.logger.addHandler(handler)

    try:
        app.config['SQLALCHEMY_DATABASE_URI'] = server.config.database.connection_string.strip("'")
    except (NoOptionError, AttributeError) as ex:
        print('Missing [database] section on server.ini. Please configure the database before running the server.')
        sys.exit(1)

    from server.models import db
    db.init_app(app)

    # from yourapplication.views.admin import admin
    # from yourapplication.views.frontend import frontend
    # app.register_blueprint(admin)
    # app.register_blueprint(frontend)

    return app


def minify_json_output(app):
    class MiniJSONEncoder(JSONEncoder):
        item_separator = ','
        key_separator = ':'

    app.json_encoder = MiniJSONEncoder
    app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

# Load APIs
import server.api
import server.modules.info
