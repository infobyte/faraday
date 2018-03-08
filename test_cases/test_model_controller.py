from Queue import Queue

import time

import mock
from managers.mapper_manager import MapperManager
from model import Modelactions
from model.controller import ModelController
from test_cases.factories import WorkspaceFactory, HostFactory


def test_controller_stop_when_is_not_processing():
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    assert controller.processing is False
    assert controller._stop is False
    controller.start()
    assert controller.isAlive()
    controller.stop()
    assert controller._stop is True
    controller.join()
    assert controller.isAlive() is False


def test_controller_cant_be_stopped_when_is_processing():
    """
        If someone tells the controller to stop and it is processing then it
        will stop when the processing finishes
    """

    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    assert controller.processing is False
    assert controller._stop is False
    controller.start()
    controller.processing = True
    controller.active_plugins_count = 1
    assert controller.isAlive()
    controller.stop()
    assert controller._stop
    assert controller.processing
    controller.join(timeout=2)
    assert controller.isAlive()
    controller.processing = False
    controller.join()
    assert controller.isAlive() is False


def test_controller_plugin_start_action_updates_internal_state():
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    controller.start()
    controller.add_action((Modelactions.PLUGINSTART, "test", None))
    time.sleep(1)
    assert controller.active_plugins_count == 1
    assert controller.processing
    controller.add_action((Modelactions.PLUGINEND, "test", None))
    time.sleep(1)
    assert controller.active_plugins_count == 0
    assert controller.processing is False
    controller.stop()
    controller.join()
    assert controller.isAlive() is False

def test_only_start_plugin():
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    controller._pluginStart('test', None)
    assert controller.active_plugins_count == 1
    assert controller.processing
    controller._pluginStart('test', None)
    assert controller.active_plugins_count == 2

def test_only_end_pluging():
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    controller._pluginStart('test', None)
    controller._pluginEnd('test', None)
    assert controller.active_plugins_count == 0
    assert controller.processing is False

def test_end_pluging_multiple_times():
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    controller._pluginEnd('test', None)
    controller._pluginEnd('test', None)
    assert controller.active_plugins_count == 0
    assert controller.processing is False


@mock.patch('persistence.server.server._get')
def test_find(get, session):
    mappers_manager = MapperManager()
    pending_actions = Queue()
    controller = ModelController(mappers_manager, pending_actions)
    workspace = WorkspaceFactory.create()
    mappers_manager.createMappers(workspace.name)
    host = HostFactory.create(workspace=workspace)
    session.commit()
    controller.find("Host", host.id)
    assert get.called
    assert get.mock_calls[0][1][0].endswith(
        '/_api/v2/ws/{0}/hosts/{1}/'.format(workspace.name, host.id))
    assert get.mock_calls[0][2] == {'object_id': host.id}

