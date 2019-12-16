import logging
from threading import Thread
from queue import Queue, Empty
import time
import os
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer
from faraday.server.api.modules.bulk_create import bulk_create

from faraday.server.models import Workspace

logger = logging.getLogger(__name__)


REPORTS_QUEUE = Queue()


class ReportsManager(Thread):

    def __init__(self, upload_reports_queue, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.upload_reports_queue = upload_reports_queue
        self.plugins_manager = PluginsManager()
        self._must_stop = False

    def stop(self):
        logger.debug("Stop Reports Manager")
        self._must_stop = True

    def send_report_request(self, workspace_name, report_json):
        logger.info("Send Report data to workspace [%s]", workspace_name)
        from faraday.server.web import app  # pylint:disable=import-outside-toplevel
        with app.app_context():
            ws = Workspace.query.filter_by(name=workspace_name).one()
            bulk_create(ws, report_json, False)

    def process_report(self, workspace, file_path):
        report_analyzer = ReportAnalyzer(self.plugins_manager)
        plugin = report_analyzer.get_plugin(file_path)
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
                    self.send_report_request(workspace, vulns_data)
                    logger.info("Report processing finished")
                except Exception as e:
                    logger.exception(e)
                    logger.error("Save Error: %s", e)
        else:
            logger.info("No plugin detected for report [%s]", file_path)

    def run(self):
        logger.debug("Start Reports Manager")
        while not self._must_stop:
            try:
                workspace, file_path = self.upload_reports_queue.get(False, timeout=0.1)
                logger.info("Processing raw report %s", file_path)
                if os.path.isfile(file_path):
                    self.process_report(workspace, file_path)
                else:
                    logger.warning("Report file [%s] don't exists", file_path)
            except Empty:
                time.sleep(0.1)
            except KeyboardInterrupt as ex:
                logger.info("Keyboard interrupt, stopping report processing thread")
                self.stop()
            except Exception as ex:
                logger.exception(ex)
                continue