# Faraday Penetration Test IDE
# Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from Queue import Empty, Queue
from multiprocessing import Queue as MultiProcessingQueue
from threading import Thread, Event

import os
import time
import string
import random
import logging
import faraday.server.config as FaradayServerConfig

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

from faraday.server.utils.logger import get_logger
from faraday.server.utils.web import gzipped

from faraday.client.model.controller import ModelController

from faraday.client.plugins.controller import PluginController
from faraday.client.plugins.manager import PluginManager

from faraday.client.managers.mapper_manager import MapperManager
from faraday.client.managers.reports_managers import ReportProcessor

from faraday.server.models import Workspace
from faraday.client.persistence.server import server

from faraday.config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()
logger = logging.getLogger(__name__)
UPLOAD_REPORTS_QUEUE = MultiProcessingQueue()
UPLOAD_REPORTS_CMD_QUEUE = MultiProcessingQueue()
upload_api = Blueprint('upload_reports', __name__)


class RawReportProcessor(Thread):
    def __init__(self):

        super(RawReportProcessor, self).__init__()
        from faraday.client.start_client import setupPlugins
        setupPlugins()

        self.pending_actions = Queue()

        try:
            plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(), "plugins"))
        except AttributeError:
            get_logger().warning(
                "Upload reports in WEB-UI not configurated, run Faraday client and try again...")
            self._stop = True
            return

        mappers_manager = MapperManager()

        self.model_controller = ModelController(mappers_manager, self.pending_actions)
        self.model_controller.start()
        self.end_event = Event()

        plugin_controller = PluginController(
            'PluginController',
            plugin_manager,
            mappers_manager,
            self.pending_actions,
            self.end_event)

        self.processor = ReportProcessor(plugin_controller, None)
        self._stop = False

    def stop(self):
        self.model_controller.stop()
        self._stop = True

    def run(self):
        logger.info('Tool report processor started')
        while not self._stop:
            try:

                workspace, file_path, cookie = UPLOAD_REPORTS_QUEUE.get(False, timeout=0.1)
                get_logger().info('Processing raw report {0}'.format(file_path))

                # Cookie of user, used to create objects in server with the right owner.
                server.FARADAY_UPLOAD_REPORTS_WEB_COOKIE = cookie
                server.FARADAY_UPLOAD_REPORTS_OVERWRITE_SERVER_URL = "http://{0}:{1}".format(
                    FaradayServerConfig.faraday_server.bind_address, FaradayServerConfig.faraday_server.port)

                self.processor.ws_name = workspace

                command_id = self.processor.processReport(file_path)
                UPLOAD_REPORTS_CMD_QUEUE.put(command_id)
                if not command_id:
                    continue

                self.end_event.wait()
                get_logger().info('Report processing of report {0} finished'.format(file_path))
                self.end_event.clear()

            except Empty:
                time.sleep(0.1)

            except KeyboardInterrupt as ex:
                get_logger().info('Keyboard interrupt, stopping report processing thread')
                self.stop()

            except Exception as ex:
                get_logger().exception(ex)
                continue


@gzipped
@upload_api.route('/v2/ws/<workspace>/upload_report', methods=['POST'])
def file_upload(workspace=None):
    """
    Upload a report file to Server and process that report with Faraday client plugins.
    """
    get_logger(__name__).debug("Importing new plugin report in server...")

    # Authorization code copy-pasted from server/api/base.py
    ws = Workspace.query.filter_by(name=workspace).one()
    if not (ws.active
            ):
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
        random_prefix = ''.join(random.choice(chars) for x in range(12))
        raw_report_filename = '{0}{1}'.format(random_prefix, secure_filename(report_file.filename))

        try:
            file_path = os.path.join(
                CONF.getConfigPath(),
                'uploaded_reports/{0}'.format(raw_report_filename))
        except AttributeError:
            get_logger().warning(
                "Upload reports in WEB-UI not configurated, run Faraday client and try again...")
            abort(make_response(jsonify(message="Upload reports not configurated: Run faraday client and start Faraday server again"), 500))

        with open(file_path, 'w') as output:
            output.write(report_file.read())

    UPLOAD_REPORTS_QUEUE.put((workspace, file_path, request.cookies))
    return make_response(jsonify(message="ok"), 200)
