from unittest.mock import patch, MagicMock

from faraday.server import tasks


class TestCallbackDebouncesFinalization:
    """The chord callback no longer finalizes inline; it debounces finalize_report per command."""

    def test_debounces_finalize_report_and_keeps_per_batch_stats(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        session.commit()

        mock_debouncer = MagicMock()
        results = [{'created': True, 'host_id': 1}, {'created': True, 'host_id': 2}]
        with patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                patch.object(tasks, 'calc_vulnerability_stats') as m_calc, \
                patch.object(tasks, 'update_host_stats') as m_update:
            tasks.on_success_process_report_task(results, command_id=command.id)

        # Per-batch host stats still run for each created host...
        assert m_calc.delay.call_count == 2
        # ...finalization is NOT done inline anymore...
        m_update.delay.assert_not_called()
        # ...it is debounced once, per command, with finalize_report.
        assert mock_debouncer.debounce.call_count == 1
        args, kwargs = mock_debouncer.debounce.call_args
        assert args[0] is tasks.finalize_report
        assert args[1] == {"command_id": command.id, "workspace_id": workspace.id}
        assert kwargs["key_suffix"] == f"cmd_id:{command.id}"

    def test_missing_command_returns_without_debouncing(self, session):
        mock_debouncer = MagicMock()
        with patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                patch.object(tasks, 'calc_vulnerability_stats'):
            tasks.on_success_process_report_task([], command_id=999999)
        mock_debouncer.debounce.assert_not_called()


class TestFinalizeReport:
    """finalize_report performs the once-per-command finalization."""

    def test_runs_finalization_once(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        session.commit()

        with patch.object(tasks, 'update_host_stats') as m_update, \
                patch.object(tasks, 'workflow_task'), \
                patch.object(tasks, 'debounce_workspace_update'):
            tasks.finalize_report(command_id=command.id, workspace_id=workspace.id)

        m_update.delay.assert_called_once()
        _, kwargs = m_update.delay.call_args
        assert kwargs["command_id"] == command.id
        assert kwargs["no_debounce"] is True  # import_source == "report"

    def test_unknown_command_is_noop(self, session, workspace):
        with patch.object(tasks, 'update_host_stats') as m_update, \
                patch.object(tasks, 'workflow_task'):
            tasks.finalize_report(command_id=999999, workspace_id=workspace.id)
        m_update.delay.assert_not_called()


def _ready(value):
    m = MagicMock()
    m.ready.return_value = value
    return m


def _finalization_patches():
    # create=True keeps these branch-safe: the notification symbols only exist on black.
    return (
        patch.object(tasks, 'update_host_stats'),
        patch.object(tasks, 'workflow_task'),
        patch.object(tasks, 'debounce_workspace_update'),
        patch.object(tasks.db.session, 'commit'),
        patch.object(tasks, 'deliver_notifications_task', create=True),
        patch.object(tasks, 'advanced_notifs_risk_and_severity_task', create=True),
        patch.object(tasks, 'BaseNotificationCreator', create=True),
        patch.object(tasks, 'should_create_notif', create=True, return_value=False),
    )


class TestFinalizeReportCompletionGate:
    """finalize_report waits until every batch chord of the command has completed."""

    def test_defers_while_a_batch_is_pending(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        command.tasks = ["c1", "c2"]
        session.commit()

        # c1 done, c2 still running.
        async_results = {"c1": _ready(True), "c2": _ready(False)}
        mock_debouncer = MagicMock()
        with patch.object(tasks.celery, 'AsyncResult', side_effect=lambda tid: async_results[tid]), \
                patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                patch.object(tasks, 'update_host_stats') as m_update:
            tasks.finalize_report(command_id=command.id, workspace_id=workspace.id, attempt=0)

        # Finalization deferred...
        m_update.delay.assert_not_called()
        # ...and re-debounced to poll again, with the attempt incremented and the same key.
        assert mock_debouncer.debounce.call_count == 1
        args, kwargs = mock_debouncer.debounce.call_args
        assert args[0] is tasks.finalize_report
        assert args[1]["attempt"] == 1
        assert kwargs["key_suffix"] == f"cmd_id:{command.id}"

    def test_finalizes_when_all_batches_ready(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        command.tasks = ["c1", "c2"]
        session.commit()

        mock_debouncer = MagicMock()
        p_stats, p_wf, p_deb, p_commit, p_deliver, p_adv, p_notif, p_should = _finalization_patches()
        with patch.object(tasks.celery, 'AsyncResult', return_value=_ready(True)), \
                patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                p_stats as m_update, p_wf, p_deb, p_commit, p_deliver, p_adv, p_notif, p_should:
            tasks.finalize_report(command_id=command.id, workspace_id=workspace.id)

        m_update.delay.assert_called_once()
        mock_debouncer.debounce.assert_not_called()  # no re-poll once everything is ready

    def test_safety_cap_finalizes_after_max_polls(self, session, workspace, command_factory):
        command = command_factory.create(workspace=workspace, import_source='report')
        command.tasks = ["c1"]
        session.commit()

        mock_debouncer = MagicMock()
        p_stats, p_wf, p_deb, p_commit, p_deliver, p_adv, p_notif, p_should = _finalization_patches()
        with patch.object(tasks.celery, 'AsyncResult', return_value=_ready(False)), \
                patch('faraday.server.app.get_debouncer', return_value=mock_debouncer), \
                p_stats as m_update, p_wf, p_deb, p_commit, p_deliver, p_adv, p_notif, p_should:
            tasks.finalize_report(command_id=command.id, workspace_id=workspace.id,
                                  attempt=tasks.FINALIZE_MAX_POLLS)

        m_update.delay.assert_called_once()  # gives up waiting and finalizes
        mock_debouncer.debounce.assert_not_called()  # no further polling past the cap
