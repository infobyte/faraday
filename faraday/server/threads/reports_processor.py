import logging
import threading
from pathlib import Path
from threading import Thread
from queue import Queue, Empty
from typing import Tuple

from faraday_plugins.plugins.manager import PluginsManager
from faraday.server.api.modules.bulk_create import bulk_create, BulkCreateSchema

from faraday.server.models import Workspace, Command, User
from faraday.server.utils.bulk_create import add_creator
from faraday.settings.reports import ReportsSettings
logger = logging.getLogger(__name__)


REPORTS_QUEUE = Queue()

INTERVAL = 0.5


class ReportsManager(Thread):

    def __init__(self, upload_reports_queue, *args, **kwargs):
        super().__init__(name="ReportsManager-Thread", daemon=True, *args, **kwargs)
        self.upload_reports_queue = upload_reports_queue
        self.plugins_manager = PluginsManager(ReportsSettings.settings.custom_plugins_folder,
                                              ignore_info=ReportsSettings.settings.ignore_info_severity)
        logger.info(f"Reports Manager: [Custom plugins folder: [{ReportsSettings.settings.custom_plugins_folder}]"
                     f"[Ignore info severity: {ReportsSettings.settings.ignore_info_severity}]")
        self.__event = threading.Event()

    def stop(self):
        logger.info("Reports Manager Thread [Stopping...]")
        self.__event.set()

    def send_report_request(self,
                            workspace_name: str,
                            command_id: int,
                            report_json: dict,
                            user_id: int):
        logger.info("Send Report data to workspace [%s]", workspace_name)
        from faraday.server.web import get_app  # pylint:disable=import-outside-toplevel
        with get_app().app_context():
            ws = Workspace.query.filter_by(name=workspace_name).one()
            command = Command.query.filter_by(id=command_id).one()
            user = User.query.filter_by(id=user_id).one()
            schema = BulkCreateSchema()
            data = schema.load(report_json)
            data = add_creator(data, user)
            bulk_create(ws, command, data, True, True)

    def process_report(self,
                       workspace_name: str,
                       command_id: int,
                       file_path: Path,
                       plugin_id: int,
                       user_id: int):
        plugin = self.plugins_manager.get_plugin(plugin_id)
        if plugin:
            try:
                logger.info(f"Processing report [{file_path}] with plugin ["
                            f"{plugin.id}")
                plugin.processReport(str(file_path))
                vulns_data = plugin.get_data()
                del vulns_data['command']['duration']
            except Exception as e:
                logger.error("Processing Error: %s", e)
                logger.exception(e)
            else:
                try:
                    self.send_report_request(
                        workspace_name, command_id, vulns_data, user_id
                    )
                    logger.info("Report processing finished")
                except Exception as e:
                    logger.exception(e)
                    logger.error("Save Error: %s", e)
        else:
            logger.info(f"No plugin detected for report [{file_path}]")

    def run(self):
        logger.info("Reports Manager Thread [Start]")

        while not self.__event.is_set():
            try:
                tpl: Tuple[str, int, Path, int, int] = \
                    self.upload_reports_queue.get(False, timeout=0.1)

                workspace_name, command_id, file_path, plugin_id, user_id = tpl

                logger.info(f"Processing raw report {file_path}")
                if file_path.is_file():
                    self.process_report(
                        workspace_name,
                        command_id,
                        file_path,
                        plugin_id,
                        user_id
                    )
                else:
                    logger.warning(f"Report file [{file_path}] don't exists",
                                   file_path)
            except Empty:
                self.__event.wait(INTERVAL)
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt, stopping report processing thread")
                self.stop()
            except Exception as ex:
                logger.exception(ex)
                continue
        else:
            logger.info("Reports Manager Thread [Stop]")
