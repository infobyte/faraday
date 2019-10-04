import logging
from threading import Thread
from queue import Queue, Empty
import time
import os
import requests
from faraday.server import config
from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer

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

    def send_report_request(self, workspace, report_json, session_cookie):
        logger.info("Send Report data to workspace [%s]", workspace)
        cookies = {'session': session_cookie}
        headers = {'Accept': 'application/json'}
        web_server_ip = config.faraday_server.bind_address
        if web_server_ip == "0.0.0.0":
            web_server_ip = "localhost"
        url = f"http://{web_server_ip}:{config.faraday_server.port}/_api/v2/ws/{workspace}/bulk_create/"
        r = requests.post(url, headers=headers, cookies=cookies, json=report_json)
        if r.status_code != requests.codes.CREATED:
            logger.warning("Bulk Create Response: %s", r.status_code)
            logger.warning("Bulk Create Response Text: %s", r.text)
            logger.debug("Data sended: %s", report_json)
        else:
            logger.debug("Report Json [%s]", report_json)
            logger.info("Bulk Create Response [%s]", r.status_code)

    def process_report(self, workspace, file_path, cookies):
        session = cookies['session']
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
                    self.send_report_request(workspace, vulns_data, session)
                except Exception as e:
                    logger.error("Save Error: %s", e)
        else:
            logger.info("No plugin detected for report [%s]", file_path)

    def run(self):
        logger.debug("Start Reports Manager")
        while not self._must_stop:
            try:
                workspace, file_path, cookies = self.upload_reports_queue.get(False, timeout=0.1)
                logger.info("Processing raw report %s", file_path)
                if os.path.isfile(file_path):
                    try:
                        self.process_report(workspace, file_path, cookies)
                    finally:
                        logger.debug("Remove report file [%s]", file_path)
                        os.remove(file_path)
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