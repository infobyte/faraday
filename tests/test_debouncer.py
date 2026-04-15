import json
from unittest.mock import MagicMock, patch

import redis as redis_lib

from faraday.server.debouncer import Debouncer, _debounce_key_for_workspace
from faraday.server.tasks import execute_debounced_action


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_debouncer(wait=10):
    """Instantiate a Debouncer with a mocked Redis client (no real connection)."""
    debouncer = Debouncer(wait=wait)
    debouncer._redis = MagicMock()
    return debouncer


def _setup_redis_first_event(debouncer):
    """Simulate first event of a burst: no existing token."""
    debouncer._redis.get.return_value = None
    debouncer._redis.incr.return_value = 1
    return 1  # new token


def _setup_redis_subsequent_event(debouncer, existing_token=1):
    """Simulate a subsequent event: token already present."""
    debouncer._redis.get.return_value = str(existing_token)
    debouncer._redis.incr.return_value = existing_token + 1
    return existing_token + 1  # new token


def _dummy_action(workspace_id):
    """Named action used to produce a predictable debounce key."""
    pass


def _make_task_redis_mock(current_token, action_name, parameters):
    """
    Build a Redis + pipeline mock suitable for execute_debounced_action tests.
    By default the pipeline reports the same token (no race) and execute() succeeds.
    """
    mock_redis = MagicMock()
    payload_json = json.dumps({"parameters": parameters})

    def _get(key):
        if key.endswith(":token"):
            return str(current_token)
        if key.endswith(":payload"):
            return payload_json
        return None

    mock_redis.get.side_effect = _get
    mock_redis.hgetall.return_value = {"action": action_name}

    mock_pipe = MagicMock()
    mock_pipe.get.return_value = str(current_token)   # token_now inside WATCH block
    mock_redis.pipeline.return_value = mock_pipe

    return mock_redis, mock_pipe


# ─── Debouncer.debounce() ─────────────────────────────────────────────────────

class TestDebounce:

    def test_first_event_schedules_celery_task_with_full_wait(self):
        """First debounce call → 'scheduled', Celery task enqueued with countdown=wait."""
        debouncer = _make_debouncer(wait=10)
        new_token = _setup_redis_first_event(debouncer)
        expected_key = _debounce_key_for_workspace("_dummy_action", 1)

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action") as mock_task, \
             patch("faraday.server.app.logger"):
            mock_server.celery_enabled = True
            debouncer.debounce(_dummy_action, {"workspace_id": 1})

        mock_task.apply_async.assert_called_once_with(
            args=[expected_key, new_token],
            countdown=10,
        )

    def test_subsequent_event_postpones_with_full_wait(self):
        """Subsequent calls increment the token and use the same countdown=wait."""
        debouncer = _make_debouncer(wait=10)
        new_token = _setup_redis_subsequent_event(debouncer, existing_token=5)
        expected_key = _debounce_key_for_workspace("_dummy_action", 1)

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action") as mock_task, \
             patch("faraday.server.app.logger"):
            mock_server.celery_enabled = True
            debouncer.debounce(_dummy_action, {"workspace_id": 1})

        mock_task.apply_async.assert_called_once_with(
            args=[expected_key, new_token],
            countdown=10,
        )

    def test_missing_workspace_id_logs_warning_and_skips_enqueue(self):
        """debounce() with no workspace_id or workspace_name → warning, no task enqueued."""
        debouncer = _make_debouncer()

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action") as mock_task, \
             patch("faraday.server.app.logger") as mock_logger:
            mock_server.celery_enabled = True
            debouncer.debounce(_dummy_action, {})

        mock_task.apply_async.assert_not_called()
        mock_logger.warning.assert_called_once()

    def test_celery_disabled_executes_action_synchronously(self):
        """When Celery is disabled, debounce() calls the action inline, no task enqueued."""
        debouncer = _make_debouncer()
        mock_action = MagicMock()
        mock_action.__name__ = "some_action"

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action") as mock_task, \
             patch("faraday.server.app.logger"):
            mock_server.celery_enabled = False
            debouncer.debounce(mock_action, {"workspace_id": 42})

        mock_action.assert_called_once_with(workspace_id=42)
        mock_task.apply_async.assert_not_called()

    def test_stores_meta_and_payload_in_redis(self):
        """debounce() writes action name (hset) and payload (set) to Redis."""
        debouncer = _make_debouncer(wait=5)
        _setup_redis_first_event(debouncer)

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action"), \
             patch("faraday.server.app.logger"):
            mock_server.celery_enabled = True
            debouncer.debounce(_dummy_action, {"workspace_id": 7})

        debouncer._redis.hset.assert_called_once()
        debouncer._redis.set.assert_called_once()

    def test_each_debounce_call_enqueues_exactly_one_task(self):
        """Every call to debounce() enqueues exactly one Celery task, never more."""
        debouncer = _make_debouncer(wait=10)
        _setup_redis_subsequent_event(debouncer, existing_token=3)

        with patch("faraday.server.debouncer.faraday_server") as mock_server, \
             patch("faraday.server.tasks.execute_debounced_action") as mock_task, \
             patch("faraday.server.app.logger"):
            mock_server.celery_enabled = True
            debouncer.debounce(_dummy_action, {"workspace_id": 1})

        assert mock_task.apply_async.call_count == 1


# ─── execute_debounced_action task ───────────────────────────────────────────

class TestExecuteDebouncedAction:

    def test_skips_when_token_key_absent(self):
        """Task exits early when the token key no longer exists in Redis (expired or already executed)."""

        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_vulns_count") as mock_action:
            execute_debounced_action("faraday:debounce:update_workspace_vulns_count:ws_id:1", 1)

        mock_action.assert_not_called()
        mock_redis.pipeline.assert_not_called()

    def test_skips_stale_token(self):
        """Task exits early when current token > expected (a newer event arrived)."""

        mock_redis = MagicMock()
        mock_redis.get.return_value = "10"  # current=10, expected=5 → stale

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_vulns_count") as mock_action:
            execute_debounced_action("faraday:debounce:update_workspace_vulns_count:ws_id:1", 5)

        mock_action.assert_not_called()
        mock_redis.pipeline.assert_not_called()

    def test_executes_vulns_count_when_token_matches(self):
        """Token match + successful claim → calls update_workspace_vulns_count."""

        debounce_key = "faraday:debounce:update_workspace_vulns_count:ws_id:42"
        token = 3
        mock_redis, _ = _make_task_redis_mock(token, "update_workspace_vulns_count", {"workspace_id": 42})

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_vulns_count") as mock_action:
            execute_debounced_action(debounce_key, token)

        mock_action.assert_called_once_with(workspace_id=42)

    def test_executes_host_count_when_token_matches(self):
        """Token match → calls update_workspace_host_count."""

        debounce_key = "faraday:debounce:update_workspace_host_count:ws_id:5"
        token = 2
        mock_redis, _ = _make_task_redis_mock(token, "update_workspace_host_count", {"workspace_id": 5})

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_host_count") as mock_action:
            execute_debounced_action(debounce_key, token)

        mock_action.assert_called_once_with(workspace_id=5)

    def test_executes_service_count_when_token_matches(self):
        """Token match → calls update_workspace_service_count."""

        debounce_key = "faraday:debounce:update_workspace_service_count:ws_id:8"
        token = 1
        mock_redis, _ = _make_task_redis_mock(token, "update_workspace_service_count", {"workspace_id": 8})

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_service_count") as mock_action:
            execute_debounced_action(debounce_key, token)

        mock_action.assert_called_once_with(workspace_id=8)

    def test_executes_update_date_when_token_matches(self):
        """Token match + update_workspace_update_date → called with {workspace_id: update_date} dict."""

        debounce_key = "faraday:debounce:update_workspace_update_date:ws_id:9"
        token = 7
        update_date = "2026-03-03T15:00:00"
        mock_redis, _ = _make_task_redis_mock(
            token, "update_workspace_update_date", {"workspace_id": 9, "update_date": update_date}
        )

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_update_date") as mock_action:
            execute_debounced_action(debounce_key, token)

        mock_action.assert_called_once_with({9: update_date})

    def test_skips_on_watch_error(self):
        """WatchError → another worker claimed execution first, this task skips."""

        debounce_key = "faraday:debounce:update_workspace_vulns_count:ws_id:1"
        token = 4
        mock_redis, mock_pipe = _make_task_redis_mock(token, "update_workspace_vulns_count", {"workspace_id": 1})
        mock_pipe.execute.side_effect = redis_lib.WatchError()

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_vulns_count") as mock_action:
            execute_debounced_action(debounce_key, token)

        mock_action.assert_not_called()

    def test_skips_when_token_changes_between_read_and_watch(self):
        """Token changes between initial read and WATCH re-read → task skips gracefully."""

        debounce_key = "faraday:debounce:update_workspace_vulns_count:ws_id:1"
        expected_token = 5
        mock_redis, mock_pipe = _make_task_redis_mock(
            expected_token, "update_workspace_vulns_count", {"workspace_id": 1}
        )
        # Token changed between outer get() and pipe.get() inside WATCH
        mock_pipe.get.return_value = "99"

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis), \
             patch("faraday.server.tasks.update_workspace_vulns_count") as mock_action:
            execute_debounced_action(debounce_key, expected_token)

        mock_action.assert_not_called()

    def test_rejects_action_not_in_allowlist(self):
        """Action names outside the explicit allowlist are rejected without execution."""

        debounce_key = "faraday:debounce:some_unknown_action:ws_id:1"
        token = 1
        mock_redis = MagicMock()

        def _get(key):
            if key.endswith(":token"):
                return str(token)
            if key.endswith(":payload"):
                return json.dumps({"parameters": {"workspace_id": 1}})
            return None

        mock_redis.get.side_effect = _get
        mock_redis.hgetall.return_value = {"action": "some_unknown_action"}

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis):
            execute_debounced_action(debounce_key, token)

        mock_redis.pipeline.assert_not_called()

    def test_pipeline_reset_called_even_on_watch_error(self):
        """pipe.reset() is always called in the finally block, even when WatchError is raised."""

        debounce_key = "faraday:debounce:update_workspace_vulns_count:ws_id:1"
        token = 2
        mock_redis, mock_pipe = _make_task_redis_mock(token, "update_workspace_vulns_count", {"workspace_id": 1})
        mock_pipe.execute.side_effect = redis_lib.WatchError()

        with patch("faraday.server.tasks.get_redis_client", return_value=mock_redis):
            execute_debounced_action(debounce_key, token)

        mock_pipe.reset.assert_called_once()
