# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information
import string
import random
import logging
from datetime import datetime
import flask_login

from faraday.server.config import CONST_FARADAY_HOME_PATH
from faraday.server.threads.reports_processor import REPORTS_QUEUE
from flask import (
    request,
    abort,
    make_response,
    jsonify,
    Blueprint,
)

from flask_wtf.csrf import validate_csrf
from werkzeug.utils import secure_filename
from wtforms import ValidationError

from faraday.server.utils.web import gzipped
from faraday.server.models import Workspace, Command, db
from faraday.settings.reports import ReportsSettings
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

upload_api = Blueprint('upload_reports', __name__)

logger = logging.getLogger(__name__)


@gzipped
@upload_api.route('/v3/ws/<workspace>/upload_report', methods=['POST'])
def file_upload(workspace=None):
    """
    ---
    post:
      tags: ["Workspace", "File"]
      description: Upload a report file to create data within the given workspace
      responses:
        201:
          description: Created
        400:
          description: Bad request
        403:
          description: Forbidden
    tags: ["Workspace", "File"]
    responses:
      200:
        description: Ok
    """
    logger.info("Importing new plugin report in server...")
    # Authorization code copy-pasted from server/api/base.py
    ws = Workspace.query.filter_by(name=workspace).first()
    if not ws or not ws.active:
        # Don't raise a 403 to prevent workspace name enumeration
        abort(404, f"Workspace disabled: {workspace}")

    if 'file' not in request.files:
        abort(400)

    try:
        validate_csrf(request.form.get('csrf_token'))
    except ValidationError:
        abort(403)

    report_file = request.files['file']

    if report_file:

        chars = string.ascii_uppercase + string.digits
        random_prefix = ''.join(random.choice(chars) for x in range(12))  # nosec
        raw_report_filename = f'{random_prefix}_{secure_filename(report_file.filename)}'

        try:
            file_path = CONST_FARADAY_HOME_PATH / 'uploaded_reports' \
                        / raw_report_filename
            with file_path.open('wb') as output:
                output.write(report_file.read())
        except AttributeError:
            logger.warning(
                "Upload reports in WEB-UI not configurated, run Faraday client and try again...")
            abort(make_response(
                jsonify(message="Upload reports not configurated: Run faraday client and start Faraday server again"),
                500))
        else:
            logger.info(f"Get plugin for file: {file_path}")
            plugins_manager = PluginsManager(ReportsSettings.settings.custom_plugins_folder)
            report_analyzer = ReportAnalyzer(plugins_manager)
            plugin = report_analyzer.get_plugin(file_path)
            if not plugin:
                logger.info("Could not get plugin for file")
                abort(make_response(jsonify(message="Invalid report file"), 400))
            else:
                logger.info(
                    f"Plugin for file: {file_path} Plugin: {plugin.id}"
                )
                workspace_instance = Workspace.query.filter_by(
                    name=workspace).one()
                command = Command()
                command.workspace = workspace_instance
                command.start_date = datetime.utcnow()
                command.import_source = 'report'
                # The data will be updated in the bulk_create function
                command.tool = "In progress"
                command.command = "In progress"

                db.session.add(command)
                db.session.commit()

                REPORTS_QUEUE.put(
                    (
                        workspace_instance.name,
                        command.id,
                        file_path,
                        plugin.id,
                        flask_login.current_user.id
                    )
                )
                return make_response(
                    jsonify(message="ok", command_id=command.id),
                    200
                )
    else:
        abort(make_response(jsonify(message="Missing report file"), 400))
