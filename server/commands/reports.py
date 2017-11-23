import os
import logging

from managers.mapper_manager import MapperManager
from managers.reports_managers import ReportManager, CONF


from plugins.controller import PluginController
from plugins.manager import PluginManager
from server.models import Workspace

logger = logging.getLogger(__name__)


def import_external_reports():
    processes = []
    plugin_manager = PluginManager(
        os.path.join(CONF.getConfigPath(), "plugins"))
    mappers_manager = MapperManager()

    plugin_controller = PluginController(
        'PluginController',
        plugin_manager,
        mappers_manager
    )
    for workspace in Workspace.query.all():
        report_manager = ReportManager(
            0.1,
            workspace.name,
            plugin_controller
        )
        processes.append(report_manager)
        report_manager.start()

    for thread in processes:
        thread.join()
