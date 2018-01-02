import os
import logging
from Queue import Queue

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
    plugins_path = os.path.join(CONF.getConfigPath(), "plugins")
    plugin_manager = PluginManager(plugins_path)
    mappers_manager = MapperManager()

    if workspace_name:
        query = Workspace.query.filter_by(name=workspace_name)
    else:
        query = Workspace.query

    process_workspaces(mappers_manager, plugin_manager, query)
    #controller._pending_actions.join()


def process_workspaces(mappers_manager, plugin_manager, query):
    report_managers = []
    controllers = []
    for workspace in query.all():
        pending_actions = Queue()
        plugin_controller = PluginController(
            'PluginController',
            plugin_manager,
            mappers_manager,
            pending_actions
        )
        mappers_manager.createMappers(workspace.name)
        controller = ModelController(mappers_manager, pending_actions)
        workspace_manager = WorkspaceManager(mappers_manager)
        setUpAPIs(controller, workspace_manager, hostname=None, port=None)
        controller.start()
        controllers.append(controller)
        report_manager = ReportManager(
            0.1,
            workspace.name,
            plugin_controller,
            polling=False
        )
        report_managers.append(report_manager)
        report_manager.start()

    #for report_manager in report_managers:
    #    report_manager.join()

    #for controller in controllers:
    #    controller.join()