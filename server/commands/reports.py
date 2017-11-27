import os
import logging

from tqdm import tqdm

from managers.mapper_manager import MapperManager
from managers.reports_managers import ReportManager, CONF
from managers.workspace_manager import WorkspaceManager
from model.api import setUpAPIs
from model.controller import ModelController

from plugins.controller import PluginController
from plugins.manager import PluginManager
from server.models import Workspace

logger = logging.getLogger(__name__)


def import_external_reports(workspace_name=None):

    plugin_manager = PluginManager(
        os.path.join(CONF.getConfigPath(), "plugins"))
    mappers_manager = MapperManager()

    plugin_controller = PluginController(
        'PluginController',
        plugin_manager,
        mappers_manager
    )

    if workspace_name:
        query = Workspace.query.filter_by(name=workspace_name)
    else:
        query = Workspace.query

    process_workspaces(mappers_manager, plugin_controller, query)
    #controller._pending_actions.join()


def process_workspaces(mappers_manager, plugin_controller, query):
    processes = []
    for workspace in query.all():
        mappers_manager.createMappers(workspace.name)
        controller = ModelController(mappers_manager)
        workspace_manager = WorkspaceManager(mappers_manager)
        setUpAPIs(controller, workspace_manager, hostname=None, port=None)
        controller.start()
        report_manager = ReportManager(
            0.1,
            workspace.name,
            plugin_controller,
            polling=False
        )
        processes.append(report_manager)
        report_manager.start()

    #for thread in tqdm(processes):
    #    thread.join()