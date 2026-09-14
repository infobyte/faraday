"""
Unit tests for faraday.server.utils.logger — celery log rotation setup.
"""
import logging
import logging.handlers
from unittest.mock import MagicMock, patch

import pytest


def test_setup_celery_logging_connects_to_both_signals_with_strong_ref():
    """setup_celery_logging must connect with weak=False to prevent GC of the closure."""
    from celery.signals import after_setup_logger, after_setup_task_logger
    from faraday.server.utils.logger import setup_celery_logging

    with patch.object(after_setup_logger, 'connect') as mock_logger_conn, \
         patch.object(after_setup_task_logger, 'connect') as mock_task_conn:
        setup_celery_logging()

    mock_logger_conn.assert_called_once()
    mock_task_conn.assert_called_once()
    _, kwargs_logger = mock_logger_conn.call_args
    _, kwargs_task = mock_task_conn.call_args
    assert kwargs_logger.get('weak') is False
    assert kwargs_task.get('weak') is False


def test_setup_celery_logging_adds_rotating_file_handler(tmp_path):
    """The handler registered for after_setup_logger adds a RotatingFileHandler with correct params."""
    from celery.signals import after_setup_logger, after_setup_task_logger
    from faraday.server.utils.logger import (
        setup_celery_logging,
        MAX_LOG_FILE_SIZE,
        MAX_LOG_FILE_BACKUP_COUNT,
    )

    captured = {}

    def capture_logger(fn, **kwargs):
        captured['fn'] = fn

    with patch.object(after_setup_logger, 'connect', side_effect=capture_logger), \
         patch.object(after_setup_task_logger, 'connect'), \
         patch('faraday.server.utils.logger.CELERY_LOG_FILE', tmp_path / 'celery.log'):
        setup_celery_logging()

    mock_logger = MagicMock(spec=logging.Logger)
    captured['fn'](logger=mock_logger)

    handlers_added = [c.args[0] for c in mock_logger.addHandler.call_args_list]
    assert len(handlers_added) == 1
    handler = handlers_added[0]
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    assert handler.maxBytes == MAX_LOG_FILE_SIZE
    assert handler.backupCount == MAX_LOG_FILE_BACKUP_COUNT


def test_setup_celery_logging_same_handler_for_task_logger(tmp_path):
    """The same RotatingFileHandler logic applies to after_setup_task_logger."""
    from celery.signals import after_setup_logger, after_setup_task_logger
    from faraday.server.utils.logger import setup_celery_logging, MAX_LOG_FILE_SIZE, MAX_LOG_FILE_BACKUP_COUNT

    captured = {}

    def capture_task(fn, **kwargs):
        captured['fn'] = fn

    with patch.object(after_setup_logger, 'connect'), \
         patch.object(after_setup_task_logger, 'connect', side_effect=capture_task), \
         patch('faraday.server.utils.logger.CELERY_LOG_FILE', tmp_path / 'celery.log'):
        setup_celery_logging()

    mock_logger = MagicMock(spec=logging.Logger)
    captured['fn'](logger=mock_logger)

    handlers_added = [c.args[0] for c in mock_logger.addHandler.call_args_list]
    assert len(handlers_added) == 1
    handler = handlers_added[0]
    assert isinstance(handler, logging.handlers.RotatingFileHandler)
    assert handler.maxBytes == MAX_LOG_FILE_SIZE
    assert handler.backupCount == MAX_LOG_FILE_BACKUP_COUNT
