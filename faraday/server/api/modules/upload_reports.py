# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import os
import string
import random
import logging

from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.threads.reports_processor import REPORTS_QUEUE
from flask import (
    request,
    abort,
    make_response,
    jsonify,
    Blueprint,
)
import flask

from flask_wtf.csrf import validate_csrf
from werkzeug.utils import secure_filename
from wtforms import ValidationError

from faraday.server.utils.web import gzipped
from faraday.server.models import Workspace
from faraday.server import config

from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

upload_api = Blueprint('upload_reports', __name__)

logger = logging.getLogger(__name__)

plugins_manager = PluginsManager(config.faraday_server.custom_plugins_folder)
report_analyzer = ReportAnalyzer(plugins_manager)

@gzipped
@upload_api.route('/v2/ws/<workspace>/upload_report', methods=['POST'])
def file_upload(workspace=None):
    """
    Upload a report file to Server and process that report with Faraday client plugins.
    """
    logger.info("Importing new plugin report in server...")
    # Authorization code copy-pasted from server/api/base.py
    ws = Workspace.query.filter_by(name=workspace).first()
    if not ws or not ws.active:
        # Don't raise a 403 to prevent workspace name enumeration
        abort(404, "Workspace disabled: %s" % workspace)

    if 'file' not in request.files:
        abort(400)

    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        abort(403)

    report_file = request.files['file']

    if report_file:

        chars = string.ascii_uppercase + string.digits
        random_prefix = ''.join(random.choice(chars) for x in range(12)) # nosec
        raw_report_filename = '{0}_{1}'.format(random_prefix, secure_filename(report_file.filename))

        try:
            file_path = os.path.join(CONST_FARADAY_HOME_PATH, 'uploaded_reports', raw_report_filename)
            with open(file_path, 'wb') as output:
                output.write(report_file.read())
        except AttributeError:
            logger.warning(
                "Upload reports in WEB-UI not configurated, run Faraday client and try again...")
            abort(make_response(jsonify(message="Upload reports not configurated: Run faraday client and start Faraday server again"), 500))
        else:
            logger.info("Get plugin for file: %s", file_path)
            plugin = report_analyzer.get_plugin(file_path)
            if not plugin:
                logger.info("Could not get plugin for file")
                abort(make_response(jsonify(message="Invalid report file"), 400))
            else:
                logger.info("Plugin for file: %s Plugin: %s", file_path, plugin.id)
                REPORTS_QUEUE.put((workspace, file_path, plugin.id, flask.g.user))
                return make_response(jsonify(message="ok"), 200)
    else:
        abort(make_response(jsonify(message="Missing report file"), 400))
# I'm Py3
