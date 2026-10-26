"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import logging
import os
import signal
import subprocess  # nosec B404
import sys
import time
from datetime import datetime, timedelta

import pytest
from sqlalchemy import text

from faraday.server.config import faraday_server
from faraday.server.models import db
from faraday.server.utils.celery import (
    _die_with_parent,
    build_celery_commands,
    get_worker_concurrency,
    release_db_connections,
    require_celery_enabled,
    spawn_celery_processes,
    terminate_celery_processes,
)
from faraday.server.utils.command import run_failed_command_stats_inline


class TestRequireCeleryEnabled:
    """The standalone faraday-worker/faraday-beat binaries must refuse to start
    when celery is disabled, instead of silently falling back to celery's
    default broker with an empty schedule."""

    def test_exits_when_celery_is_disabled(self, monkeypatch):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        with pytest.raises(SystemExit):
            require_celery_enabled('beat')

    def test_returns_when_celery_is_enabled(self, monkeypatch):
        monkeypatch.setattr(faraday_server, 'celery_enabled', True)
        require_celery_enabled('beat')


class TestReleaseDbConnections:
    """Beat and the worker parents open connections while creating the app and
    never check them out again, so they must be closed before celery starts."""

    def test_closes_the_connections_left_idle_in_the_pool(self, app):
        with db.engine.connect() as connection:
            connection.execute(text('SELECT 1'))
        assert db.engine.pool.checkedin() > 0

        release_db_connections(app)

        assert db.engine.pool.checkedin() == 0

    def test_beat_releases_them_before_starting(self, monkeypatch):
        import faraday.server.celery_beat as celery_beat  # pylint: disable=import-outside-toplevel
        calls = []
        monkeypatch.setattr(sys, 'argv', ['faraday-beat'])
        monkeypatch.setattr(celery_beat, 'require_celery_enabled', lambda name: None)
        monkeypatch.setattr(celery_beat, 'get_app', lambda: 'app')
        monkeypatch.setattr(celery_beat, 'setup_celery_logging', lambda: None)
        monkeypatch.setattr(celery_beat, 'release_db_connections', lambda app: calls.append(('release', app)))
        monkeypatch.setattr(celery_beat.celery, 'start', lambda argv: calls.append(('start', argv[0])))

        celery_beat.main()

        assert calls == [('release', 'app'), ('start', 'beat')]

    def test_prefork_worker_releases_them_before_forking(self, monkeypatch):
        import faraday.server.celery_worker as celery_worker  # pylint: disable=import-outside-toplevel
        calls = []
        monkeypatch.setattr(sys, 'argv', ['faraday-worker', '--concurrency', '2'])
        monkeypatch.setattr(celery_worker, 'require_celery_enabled', lambda name: None)
        monkeypatch.setattr(celery_worker, 'get_app', lambda: 'app')
        monkeypatch.setattr(celery_worker, 'setup_celery_logging', lambda: None)
        monkeypatch.setattr(celery_worker, 'release_db_connections', lambda app: calls.append(('release', app)))
        monkeypatch.setattr(celery_worker.celery, 'worker_main', lambda argv: calls.append(('start', argv[0])))

        celery_worker.main()

        assert calls == [('release', 'app'), ('start', 'worker')]


class TestWorkerConcurrency:
    """os.cpu_count() reports the node's cores, not the container's CPU limit,
    and each prefork process opens its own database connection, so the
    automatic concurrency is capped by celery_max_worker_concurrency."""

    @pytest.fixture(autouse=True)
    def default_cap(self, monkeypatch):
        monkeypatch.setattr(faraday_server, 'celery_max_worker_concurrency', 2)

    def test_default_cap_is_two(self):
        from faraday.server.config import FaradayServerConfigObject  # pylint: disable=import-outside-toplevel
        assert FaradayServerConfigObject().celery_max_worker_concurrency == 2

    def test_explicit_flag_wins_over_the_cap(self, monkeypatch):
        monkeypatch.setattr(os, 'cpu_count', lambda: 16)
        assert get_worker_concurrency('8') == '8'

    def test_spare_cores_are_capped(self, monkeypatch):
        monkeypatch.setattr(os, 'cpu_count', lambda: 16)
        assert get_worker_concurrency() == 2

    def test_cap_is_read_from_config(self, monkeypatch):
        monkeypatch.setattr(os, 'cpu_count', lambda: 16)
        monkeypatch.setattr(faraday_server, 'celery_max_worker_concurrency', 4)
        assert get_worker_concurrency() == 4

    def test_fewer_spare_cores_than_the_cap(self, monkeypatch):
        monkeypatch.setattr(os, 'cpu_count', lambda: 2)
        assert get_worker_concurrency() == 1

    @pytest.mark.parametrize('cores', [1, None])
    def test_never_below_one_process(self, monkeypatch, cores):
        monkeypatch.setattr(os, 'cpu_count', lambda: cores)
        assert get_worker_concurrency() == 1

    def test_prefork_worker_uses_it_when_no_flag_is_given(self, monkeypatch):
        import faraday.server.celery_worker as celery_worker  # pylint: disable=import-outside-toplevel
        started = []
        monkeypatch.setattr(os, 'cpu_count', lambda: 16)
        monkeypatch.setattr(sys, 'argv', ['faraday-worker'])
        monkeypatch.setattr(celery_worker, 'require_celery_enabled', lambda name: None)
        monkeypatch.setattr(celery_worker, 'get_app', lambda: 'app')
        monkeypatch.setattr(celery_worker, 'release_db_connections', lambda app: None)
        monkeypatch.setattr(celery_worker, 'setup_celery_logging', lambda: None)
        monkeypatch.setattr(celery_worker.celery, 'worker_main', started.append)

        celery_worker.main()

        argv = started[0]
        assert argv[argv.index('--concurrency') + 1] == 2


class TestBuildCeleryCommands:
    """The server spawns these as plain subprocesses. Passing them through `sh`
    deadlocks the server: gevent's monkey patch defers os.close to the next loop
    iteration, so sh's post-fork handshake read never sees EOF and the server
    never reaches socketio.run."""

    def test_no_flags_spawns_nothing(self):
        assert build_celery_commands() == []

    def test_workers_forward_every_option(self):
        assert build_celery_commands(with_workers=True, queue='reports',
                                     concurrency='4', loglevel='INFO') == [
            ['faraday-worker', '--queue', 'reports', '--concurrency', '4', '--loglevel', 'INFO']
        ]

    def test_workers_omit_options_that_were_not_given(self):
        assert build_celery_commands(with_workers=True) == [['faraday-worker']]

    def test_gevent_workers_take_concurrency_and_loglevel(self):
        assert build_celery_commands(with_workers_gevent=True, concurrency='8',
                                     loglevel='DEBUG') == [
            ['faraday-worker-gevent', '--concurrency', '8', '--loglevel', 'DEBUG']
        ]

    def test_prefork_workers_win_when_both_modes_are_given(self):
        assert build_celery_commands(with_workers=True, with_workers_gevent=True) == [
            ['faraday-worker']
        ]

    def test_beat_runs_next_to_the_workers(self):
        assert build_celery_commands(with_workers=True, with_beat=True, loglevel='WARNING') == [
            ['faraday-worker', '--loglevel', 'WARNING'],
            ['faraday-beat', '--loglevel', 'WARNING'],
        ]

    def test_beat_alone(self):
        assert build_celery_commands(with_beat=True) == [['faraday-beat']]


class TestCeleryProcessLifecycle:
    """Workers and beat started by the server must not outlive it."""

    def test_terminate_stops_the_spawned_processes(self):
        processes = spawn_celery_processes([['sleep', '120'], ['sleep', '120']])
        assert all(process.poll() is None for process in processes)

        terminate_celery_processes(processes)

        assert [process.poll() for process in processes] == [-signal.SIGTERM] * 2

    def test_terminate_kills_processes_that_ignore_sigterm(self):
        stubborn = ('import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); '
                    'time.sleep(120)')
        processes = spawn_celery_processes([[sys.executable, '-c', stubborn]])
        # Give the child time to install its handler, otherwise it dies on SIGTERM.
        time.sleep(2)

        terminate_celery_processes(processes, timeout=2)

        assert processes[0].poll() == -signal.SIGKILL

    def test_terminate_does_not_fail_on_processes_that_already_exited(self):
        processes = spawn_celery_processes([[sys.executable, '-c', 'pass']])
        processes[0].wait(timeout=30)

        terminate_celery_processes(processes)

        assert processes[0].poll() == 0

    def test_terminate_without_processes(self):
        terminate_celery_processes([])

    @pytest.mark.skipif(not sys.platform.startswith('linux'),
                        reason='PR_SET_PDEATHSIG is linux only')
    def test_spawned_processes_die_when_the_server_dies_abruptly(self, tmp_path):
        pid_file = tmp_path / 'child.pid'
        spawner = (
            'import os, sys, time;'
            'from faraday.server.utils.celery import spawn_celery_processes;'
            "processes = spawn_celery_processes([['sleep', '120']]);"
            f"open({str(pid_file)!r}, 'w').write(str(processes[0].pid));"
            'time.sleep(0.5);'
            'os._exit(0)'
        )
        subprocess.run([sys.executable, '-c', spawner], check=True, timeout=60)  # nosec B603
        child_pid = int(pid_file.read_text())

        alive = True
        for _ in range(50):
            try:
                os.kill(child_pid, 0)
            except OSError:
                alive = False
                break
            time.sleep(0.1)

        assert not alive, f'process {child_pid} outlived the server that spawned it'

    @pytest.mark.skipif(not sys.platform.startswith('linux'),
                        reason='PR_SET_PDEATHSIG is linux only')
    def test_child_gives_up_when_the_server_died_before_pdeathsig_was_set(self):
        # PR_SET_PDEATHSIG is not retroactive: a child that gets reparented before
        # registering it never receives the signal, so it has to check by itself.
        never_our_parent = os.getpid() + 1

        pid = os.fork()
        if pid == 0:
            try:
                _die_with_parent(never_our_parent)
            finally:
                os._exit(0)  # pylint: disable=protected-access

        _, status = os.waitpid(pid, 0)

        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 1, \
            'child kept running with a parent that can no longer signal it'


class TestRunFailedCommandStatsInline:
    """With celery disabled there is no beat scheduler, so the server runs
    update_failed_command_stats itself on boot."""

    def test_selects_only_hosts_of_recent_failed_commands(
        self,
        monkeypatch,
        caplog,
        app,
        session,
        workspace,
        host_factory,
        vulnerability_factory,
        command_factory,
        command_object_factory,
    ):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        recent_command = command_factory.create(workspace=workspace,
                                                end_date=None,
                                                create_date=datetime.utcnow())
        old_command = command_factory.create(workspace=workspace,
                                             end_date=None,
                                             create_date=datetime.utcnow() - timedelta(days=10))
        recent_host = host_factory.create(workspace=workspace)
        old_host = host_factory.create(workspace=workspace)
        session.add_all([recent_command, old_command, recent_host, old_host])
        session.commit()

        session.add_all([
            command_object_factory.create(command_id=recent_command.id,
                                          object_id=recent_host.id,
                                          object_type='host',
                                          created_persistent=True,
                                          workspace=workspace),
            command_object_factory.create(command_id=old_command.id,
                                          object_id=old_host.id,
                                          object_type='host',
                                          created_persistent=True,
                                          workspace=workspace),
            vulnerability_factory.create(workspace=workspace, host=recent_host,
                                         service=None, confirmed=True,
                                         status='open', severity='high'),
            vulnerability_factory.create(workspace=workspace, host=old_host,
                                         service=None, confirmed=True,
                                         status='open', severity='high'),
        ])
        session.commit()
        recent_host_id, old_host_id = recent_host.id, old_host.id

        with caplog.at_level(logging.DEBUG, logger='faraday.server.tasks'):
            run_failed_command_stats_inline(app)

        stats_calls = [r.message for r in caplog.records
                       if r.message.startswith('Calculating vulns stats for host')]
        assert f'Calculating vulns stats for host {recent_host_id}' in stats_calls
        # Commands older than 7 days are skipped, so this host is left untouched.
        assert f'Calculating vulns stats for host {old_host_id}' not in stats_calls

    def test_does_not_raise_when_there_is_nothing_to_update(self, monkeypatch, app, session, workspace):
        monkeypatch.setattr(faraday_server, 'celery_enabled', False)
        session.commit()
        run_failed_command_stats_inline(app)

    def test_swallows_task_errors_so_the_server_still_boots(self, monkeypatch, caplog, app):
        def boom(*args, **kwargs):
            raise RuntimeError('broken')

        monkeypatch.setattr('faraday.server.tasks.update_failed_command_stats', boom)

        with caplog.at_level(logging.ERROR, logger='faraday.server.utils.command'):
            run_failed_command_stats_inline(app)

        assert any('broken' in r.message for r in caplog.records)
