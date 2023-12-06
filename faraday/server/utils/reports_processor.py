"""
Faraday Penetration Test IDE
Copyright (C) 2019  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional, Tuple
from queue import Queue, Empty

from gevent.event import Event

from faraday_plugins.plugins.manager import PluginsManager
from faraday.server.api.modules.bulk_create import bulk_create, BulkCreateSchema
from faraday.server.config import faraday_server
from faraday.server.extensions import socketio
from faraday.server.models import (
    Workspace,
    Command,
    User,
    db,
)
from faraday.server.utils.bulk_create import add_creator
from faraday.settings.reports import ReportsSettings

logger = logging.getLogger(__name__)

REPORTS_QUEUE = Queue()
INTERVAL = 0.5

stop_reports_event = Event()


def reports_manager_background_task():
    while not stop_reports_event.is_set():
        try:
            tpl: Tuple[str, int, Path, int, int, bool, bool, list, list, list] = REPORTS_QUEUE.get(False, timeout=0.1)

            workspace_name, command_id, file_path, plugin_id, user_id, ignore_info_bool, dns_resolution, vuln_tag, \
            host_tag, service_tag = tpl

            logger.info(f"Processing raw report {file_path} with background task ")
            if file_path.is_file():
                process_report(workspace_name,
                               command_id,
                               file_path,
                               plugin_id,
                               user_id,
                               ignore_info_bool,
                               dns_resolution,
                               vuln_tag,
                               host_tag,
                               service_tag)
            else:
                logger.warning(f"Report file [{file_path}] does not exist",
                               file_path)
        except Empty:
            socketio.sleep(INTERVAL)
    else:
        logger.info("Reports processor stopped")


def command_status_error(command_id: int):
    command = Command.query.filter_by(id=command_id).first()
    command.command = "error"
    db.session.commit()


def send_report_data(workspace_name: str, command_id: int, report_json: dict,
                     user_id: Optional[int], set_end_date: bool):
    logger.info("Send Report data to workspace [%s]", workspace_name)
    ws = Workspace.query.filter_by(name=workspace_name).one()
    command = Command.query.filter_by(id=command_id).one()
    schema = BulkCreateSchema()
    data = schema.load(report_json)
    if user_id:
        user = User.query.filter_by(id=user_id).one()
        data = add_creator(data, user)
    return bulk_create(ws, command, data, True, set_end_date)


def process_report(workspace_name: str, command_id: int, file_path: Path,
                   plugin_id: Optional[int], user_id: Optional[int], ignore_info: bool, dns_resolution: bool,
                   vuln_tag: Optional[list] = None, host_tag: Optional[list] = None, service_tag: Optional[list] = None):
    from faraday.server.app import get_app  # pylint: disable=import-outside-toplevel
    with get_app().app_context():
        if plugin_id is not None:
            plugins_manager = PluginsManager(ReportsSettings.settings.custom_plugins_folder,
                                             ignore_info=ignore_info,
                                             hostname_resolution=dns_resolution,
                                             vuln_tag=vuln_tag,
                                             host_tag=host_tag,
                                             service_tag=service_tag)
            logger.info(f"Reports Manager: [Custom plugins folder: "
                        f"[{ReportsSettings.settings.custom_plugins_folder}]"
                        f"[Ignore info severity: {ignore_info}]"
                        f"[Hostname resolution: {dns_resolution}]"
                        f"[Vuln tag: {vuln_tag}]"
                        f"[Host tag: {host_tag}]"
                        f"[Service tag: {service_tag}]")
            plugin = plugins_manager.get_plugin(plugin_id)
            if plugin:
                try:
                    logger.info(f"Processing report [{file_path}] with plugin ["
                                f"{plugin.id}]")
                    plugin.processReport(str(file_path))
                    vulns_data = plugin.get_data()
                    del vulns_data['command']['duration']
                except Exception as e:
                    logger.error(f"Processing Error: {e}")
                    logger.exception(e)
                    command_status_error(command_id)
                    return
            else:
                logger.error(f"No plugin detected for report [{file_path}]")
                command_status_error(command_id)
                return
        else:
            try:
                with file_path.open("r") as f:
                    vulns_data = json.load(f)
            except Exception as e:
                logger.error("Loading data from json file: %s [%s]", file_path, e)
                logger.exception(e)
                command_status_error(command_id)
                return
        if plugin_id is None:
            logger.debug("Removing file: %s", file_path)
            os.remove(file_path)
        else:
            if faraday_server.delete_report_after_process:
                os.remove(file_path)
        set_end_date = True
        try:
            return send_report_data(workspace_name, command_id, vulns_data, user_id, set_end_date)
        except Exception as e:
            logger.exception(e)
            logger.error("Save Error: %s", e)
            command_status_error(command_id)
