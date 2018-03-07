from Queue import Queue

import time

from managers.mapper_manager import MapperManager
from model import Modelactions
from model.controller import ModelController


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