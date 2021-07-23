import logging
import os
import threading
from pathlib import Path
from threading import Thread
from queue import Queue, Empty
from typing import Tuple, Optional
import json
import multiprocessing

from faraday_plugins.plugins.manager import PluginsManager
from faraday.server.api.modules.bulk_create import bulk_create, BulkCreateSchema

from faraday.server.models import Workspace, Command, User
from faraday.server.utils.bulk_create import add_creator
from faraday.settings.reports import ReportsSettings
from faraday.server.config import faraday_server

logger = logging.getLogger(__name__)


REPORTS_QUEUE = Queue()
INTERVAL = 0.5


def send_report_data(workspace_name: str, command_id: int, report_json: dict,
                     user_id: Optional[int], set_end_date: bool):
    logger.info("Send Report data to workspace [%s]", workspace_name)
    from faraday.server.web import get_app  # pylint:disable=import-outside-toplevel
    with get_app().app_context():
        ws = Workspace.query.filter_by(name=workspace_name).one()
        command = Command.query.filter_by(id=command_id).one()
        schema = BulkCreateSchema()
        data = schema.load(report_json)
        if user_id:
            user = User.query.filter_by(id=user_id).one()
            data = add_creator(data, user)
        bulk_create(ws, command, data, True, set_end_date)


def process_report(workspace_name: str, command_id: int, file_path: Path,
                   plugin_id: Optional[int], user_id: Optional[int]):
    if plugin_id is not None:
        plugins_manager = PluginsManager(ReportsSettings.settings.custom_plugins_folder,
                                         ignore_info=ReportsSettings.settings.ignore_info_severity)
        logger.info(f"Reports Manager: [Custom plugins folder: "
                    f"[{ReportsSettings.settings.custom_plugins_folder}]"
                    f"[Ignore info severity: {ReportsSettings.settings.ignore_info_severity}]")
        plugin = plugins_manager.get_plugin(plugin_id)
        if plugin:
            try:
                logger.info(f"Processing report [{file_path}] with plugin ["
                            f"{plugin.id}]")
                plugin.processReport(str(file_path))
                vulns_data = plugin.get_data()
                del vulns_data['command']['duration']
            except Exception as e:
                logger.error("Processing Error: %s", e)
                logger.exception(e)
                return
        else:
            logger.error(f"No plugin detected for report [{file_path}]")
            return
    else:
        try:
            with file_path.open("r") as f:
                vulns_data = json.load(f)
        except Exception as e:
            logger.error("Loading data from json file: %s [%s]", file_path, e)
            logger.exception(e)
            return
    if plugin_id is None:
        logger.debug("Removing file: %s", file_path)
        os.remove(file_path)
    else:
        if faraday_server.delete_report_after_process:
            os.remove(file_path)
    set_end_date = True
    try:
        send_report_data(workspace_name, command_id, vulns_data, user_id, set_end_date)
        logger.info("Report processing finished")
    except Exception as e:
        logger.exception(e)
        logger.error("Save Error: %s", e)


class ReportsManager(Thread):

    def __init__(self, upload_reports_queue, *args, **kwargs):
        super().__init__(name="ReportsManager-Thread", daemon=True, *args, **kwargs)
        self.upload_reports_queue = upload_reports_queue
        self.__event = threading.Event()
        self.processing_pool = multiprocessing.Pool(processes=faraday_server.reports_pool_size)

    def stop(self):
        logger.info("Reports Manager Thread [Stopping...]")
        self.__event.set()

    def run(self):
        logger.info(f"Reports Manager Thread [Start] with Pool Size: {faraday_server.reports_pool_size}")
        while not self.__event.is_set():
            try:
                tpl: Tuple[str, int, Path, int, int] = \
                    self.upload_reports_queue.get(False, timeout=0.1)

                workspace_name, command_id, file_path, plugin_id, user_id = tpl

                logger.info(f"Processing raw report {file_path}")
                if file_path.is_file():
                    self.processing_pool.apply_async(process_report,
                                                     (workspace_name, command_id, file_path, plugin_id, user_id))
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
            self.processing_pool.close()
            self.processing_pool.terminate()
            self.processing_pool.join()
