"""
Faraday Penetration Test IDE
Copyright (C) 2025  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
import ctypes
import logging
import os
import signal
import subprocess  # nosec B404
import sys
from functools import partial
from typing import List, Optional

from faraday.server.config import faraday_server

logger = logging.getLogger(__name__)

PR_SET_PDEATHSIG = 1
TERMINATE_TIMEOUT = 15

if sys.platform.startswith('linux'):
    try:
        _libc = ctypes.CDLL('libc.so.6', use_errno=True)
    except OSError:
        _libc = None
else:
    _libc = None


def _die_with_parent(parent_pid: int) -> None:
    """Ask the kernel to signal us when the server that spawned us dies.

    Covers what the shutdown path cannot: a crash or a SIGKILL on the server
    would otherwise leave its workers running.
    """
    if _libc is None:
        return
    _libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
    # The signal is not retroactive: if the server died before the call above we
    # were already reparented and it will never arrive, so exit right away.
    if os.getppid() != parent_pid:
        os._exit(1)  # pylint: disable=protected-access


def build_celery_commands(with_workers: bool = False,
                          with_workers_gevent: bool = False,
                          with_beat: bool = False,
                          queue: Optional[str] = None,
                          concurrency: Optional[str] = None,
                          loglevel: Optional[str] = None) -> List[List[str]]:
    """Command lines of the celery processes the server has to spawn."""
    commands = []

    if with_workers:
        worker_cmd = ['faraday-worker']
        if queue:
            worker_cmd += ['--queue', queue]
        if concurrency:
            worker_cmd += ['--concurrency', concurrency]
        if loglevel:
            worker_cmd += ['--loglevel', loglevel]
        commands.append(worker_cmd)
    elif with_workers_gevent:
        worker_cmd = ['faraday-worker-gevent']
        if concurrency:
            worker_cmd += ['--concurrency', concurrency]
        if loglevel:
            worker_cmd += ['--loglevel', loglevel]
        commands.append(worker_cmd)

    if with_beat:
        beat_cmd = ['faraday-beat']
        if loglevel:
            beat_cmd += ['--loglevel', loglevel]
        commands.append(beat_cmd)

    return commands


def spawn_celery_processes(commands: List[List[str]]) -> List[subprocess.Popen]:
    """Start the celery processes as children of the server.

    Spawned with subprocess, never with sh: gevent's monkey patch defers
    os.close until the next loop iteration, so sh's post-fork handshake read
    never sees EOF and the server hangs before it starts serving.
    """
    processes = []
    server_pid = os.getpid()
    for command in commands:
        logger.info("Starting %s", command[0])
        processes.append(
            # _die_with_parent only calls prctl and getppid, and gevent turns the server's
            # threads into greenlets, so the fork/threads hazard of preexec_fn does not apply.
            # pylint: disable-next=subprocess-popen-preexec-fn
            subprocess.Popen(command,  # nosec B603
                             preexec_fn=partial(_die_with_parent, server_pid))
        )
    return processes


def terminate_celery_processes(processes: List[subprocess.Popen],
                               timeout: int = TERMINATE_TIMEOUT) -> None:
    """Stop the celery processes the server spawned, warm shutdown first."""
    running = [process for process in processes if process.poll() is None]

    for process in running:
        logger.info("Stopping celery process %s", process.pid)
        try:
            process.terminate()
        except OSError:
            pass

    for process in running:
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Celery process %s did not stop, killing it", process.pid)
            process.kill()
            process.wait()


def require_celery_enabled(process_name: str) -> None:
    """Abort when celery is disabled.

    Without it the celery object never gets the app config, so the process
    would start against celery's default broker with an empty schedule and
    no registered tasks, without logging any error.
    """
    if not faraday_server.celery_enabled:
        print(f"In order to run faraday {process_name} you must set "
              f"`celery_enabled=True` in your server.ini")
        sys.exit(1)
