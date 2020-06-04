import logging
import threading
from threading import Thread
from queue import Queue, Empty
import os
from faraday_plugins.plugins.manager import PluginsManager
from faraday.server.api.modules.bulk_create import bulk_create, BulkCreateSchema
from faraday.server import config

from faraday.server.models import Workspace
from faraday.server.utils.bulk_create import add_creator

logger = logging.getLogger(__name__)


REPORTS_QUEUE = Queue()


class ReportsManager(Thread):

    def __init__(self, upload_reports_queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.upload_reports_queue = upload_reports_queue
        self.plugins_manager = PluginsManager(config.faraday_server.custom_plugins_folder)
        self.__event = threading.Event()

    def stop(self):
        logger.debug("Stop Reports Manager")
        self.__event.set()

    def send_report_request(self, workspace_name, report_json, user):
        logger.info("Send Report data to workspace [%s]", workspace_name)
        from faraday.server.web import app  # pylint:disable=import-outside-toplevel
        with app.app_context():
            ws = Workspace.query.filter_by(name=workspace_name).one()
            schema = BulkCreateSchema()
            data = schema.load(report_json)
            data = add_creator(data, user)
            bulk_create(ws, data, True)

    def process_report(self, workspace, file_path, plugin_id, user):
        plugin = self.plugins_manager.get_plugin(plugin_id)
        if plugin:
            try:
                logger.info("Processing report [%s] with plugin [%s]", file_path, plugin.id)
                plugin.processReport(file_path)
                vulns_data = plugin.get_data()
            except Exception as e:
                logger.error("Processing Error: %s", e)
                logger.exception(e)
            else:
                try:
                    self.send_report_request(workspace, vulns_data, user)
                    logger.info("Report processing finished")
                except Exception as e:
                    logger.exception(e)
                    logger.error("Save Error: %s", e)
        else:
            logger.info("No plugin detected for report [%s]", file_path)

    def run(self):
        logger.debug("Start Reports Manager")
        while not self.__event.is_set():
            try:
                workspace, file_path, plugin_id, user = self.upload_reports_queue.get(False, timeout=0.1)
                logger.info("Processing raw report %s", file_path)
                if os.path.isfile(file_path):
                    self.process_report(workspace, file_path, plugin_id, user)
                else:
                    logger.warning("Report file [%s] don't exists", file_path)
            except Empty:
                self.__event.wait(0.1)
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt, stopping report processing thread")
                self.stop()
            except Exception as ex:
                logger.exception(ex)
                continue
