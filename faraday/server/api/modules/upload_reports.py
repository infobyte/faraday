"""
Faraday Penetration Test IDE
Copyright (C) 2018  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import string
import random
import logging
from datetime import datetime

# Related third party imports
import flask_login
from flask import (
    Blueprint,
    request,
    abort,
    make_response,
    jsonify,
)
from flask_classful import route
from flask_wtf.csrf import validate_csrf
from marshmallow import Schema
from werkzeug.utils import secure_filename
from wtforms import ValidationError

# Local application imports
from faraday.server.api.base import GenericWorkspacedView
from faraday.server.config import CONST_FARADAY_HOME_PATH, faraday_server
from faraday.server.models import Workspace, Command, db
from faraday.server.utils.reports_processor import REPORTS_QUEUE
from faraday.server.utils.web import gzipped
from faraday.settings.reports import ReportsSettings
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday.server.tasks import pre_process_report_task

upload_api = Blueprint('upload_reports', __name__)
logger = logging.getLogger(__name__)


class EmptySchema(Schema):
    pass


class UploadReportView(GenericWorkspacedView):
    route_base = 'upload_report'
    schema_class = EmptySchema

    @gzipped
    @route('', methods=['POST'])
    def file_upload(self, workspace_name=None):
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
        ws = Workspace.query.filter_by(name=workspace_name).first()
        if not ws or not ws.active:
            # Don't raise a 403 to prevent workspace name enumeration
            abort(404, f"Workspace disabled: {workspace_name}")

        if 'file' not in request.files:
            abort(400)

        try:
            validate_csrf(request.form.get('csrf_token'))
        except ValidationError:
            abort(403)

        report_file = request.files['file']

        ignore_info = True if request.form.get('ignore_info') in ("True", "true") else False  # pylint: disable=R1719

        resolve_hostname = True if request.form.get('resolve_hostname') in ("True", "true")\
            else False  # pylint: disable=R1719

        if report_file:

            chars = string.ascii_uppercase + string.digits
            random_prefix = ''.join(random.choice(chars) for _ in range(12))  # nosec
            raw_report_filename = f'{random_prefix}_{secure_filename(report_file.filename)}'

            try:
                file_path = CONST_FARADAY_HOME_PATH / 'uploaded_reports' \
                            / raw_report_filename
                with file_path.open('wb') as output:
                    output.write(report_file.read())
            except AttributeError:
                logger.warning(
                    "Upload reports in WEB-UI not configured, run Faraday client and try again...")
                abort(make_response(
                    jsonify(message="Upload reports not configured: Run faraday client and start Faraday server again"),
                    500))
            else:
                workspace_instance = Workspace.query.filter_by(
                    name=workspace_name).one()
                command = Command()
                command.workspace = workspace_instance
                command.start_date = datetime.utcnow()
                command.import_source = 'report'
                # The data will be updated in the bulk_create function
                command.tool = "In progress"
                command.command = "In progress"

                db.session.add(command)
                db.session.commit()

                if faraday_server.celery_enabled:
                    try:
                        pre_process_report_task.delay(
                            workspace_instance.name,
                            command.id,
                            file_path.as_posix(),
                            None,
                            flask_login.current_user.id,
                            ignore_info,
                            resolve_hostname,
                            None,
                            None,
                            None
                        )
                    except Exception as e:
                        logger.exception("An error occurred while process report was running %s", exc_info=e)
                        abort(make_response(jsonify(message="An error occurred while process report was running"), 500))
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
                        REPORTS_QUEUE.put(
                            (
                                workspace_instance.name,
                                command.id,
                                file_path,
                                plugin.id,
                                flask_login.current_user.id,
                                ignore_info,
                                resolve_hostname,
                                None,
                                None,
                                None
                            )
                        )
                return make_response(
                    jsonify(message="ok", command_id=command.id),
                    200
                )
        else:
            abort(make_response(jsonify(message="Missing report file"), 400))


UploadReportView.register(upload_api)
