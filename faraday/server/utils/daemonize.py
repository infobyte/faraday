"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information

Copyright (C) 2005 Chad J. Schroeder
Modified version of a script created by Chad J. Schroeder, obtained from
https://code.activestate.com/recipes/278731-creating-a-daemon-the-python-way/
"""
# Standard library imports
import atexit
import errno
import logging
import os
import re
import signal
import sys
from functools import partial
from pathlib import Path

# Local application imports
from faraday.server.config import (
    CONST_FARADAY_HOME_PATH,
    FARADAY_SERVER_PID_FILE,
    FARADAY_BASE
)

logger = logging.getLogger(__name__)

# Default daemon parameters.
# File mode creation mask of the daemon.
UMASK = 0

# Default working directory for the daemon.
WORKDIR = "/"

# The standard I/O file descriptors are redirected to /dev/null by default.
if hasattr(os, "devnull"):
    REDIRECT_TO = os.devnull
else:
    REDIRECT_TO = "/dev/null"


def createDaemon():
    """Detach a process from the controlling terminal and run it in the
    background as a daemon.
    """

    try:
        # Fork a child process so the parent can exit.  This returns control to
        # the command-line or shell.  It also guarantees that the child will not
        # be a process group leader, since the child receives a new process ID
        # and inherits the parent's process group ID.  This step is required
        # to insure that the next call to os.setsid is successful.
        pid = os.fork()
    except OSError as e:
        raise OSError(f"{e.strerror} [{e.errno}]") from e

    if pid == 0:  # The first child.
        # To become the session leader of this new session and the process group
        # leader of the new process group, we call os.setsid().  The process is
        # also guaranteed not to have a controlling terminal.
        os.setsid()

        # Is ignoring SIGHUP necessary?
        #
        # It's often suggested that the SIGHUP signal should be ignored before
        # the second fork to avoid premature termination of the process.  The
        # reason is that when the first child terminates, all processes, e.g.
        # the second child, in the orphaned group will be sent a SIGHUP.
        #
        # "However, as part of the session management system, there are exactly
        # two cases where SIGHUP is sent on the death of a process:
        #
        #   1) When the process that dies is the session leader of a session that
        #      is attached to a terminal device, SIGHUP is sent to all processes
        #      in the foreground process group of that terminal device.
        #   2) When the death of a process causes a process group to become
        #      orphaned, and one or more processes in the orphaned group are
        #      stopped, then SIGHUP and SIGCONT are sent to all members of the
        #      orphaned group." [2]
        #
        # The first case can be ignored since the child is guaranteed not to have
        # a controlling terminal.  The second case isn't so easy to dismiss.
        # The process group is orphaned when the first child terminates and
        # POSIX.1 requires that every STOPPED process in an orphaned process
        # group be sent a SIGHUP signal followed by a SIGCONT signal.  Since the
        # second child is not STOPPED though, we can safely forego ignoring the
        # SIGHUP signal.  In any case, there are no ill-effects if it is ignored.
        #
        # import signal           # Set handlers for asynchronous events.
        # signal.signal(signal.SIGHUP, signal.SIG_IGN)

        try:
            # Fork a second child and exit immediately to prevent zombies.  This
            # causes the second child process to be orphaned, making the init
            # process responsible for its cleanup.  And, since the first child is
            # a session leader without a controlling terminal, it's possible for
            # it to acquire one by opening a terminal in the future (System V-
            # based systems).  This second fork guarantees that the child is no
            # longer a session leader, preventing the daemon from ever acquiring
            # a controlling terminal.
            pid = os.fork()  # Fork a second child.
        except OSError as e:
            raise OSError(f"{e.strerror} [{e.errno}]") from e

        if pid == 0:  # The second child.
            # Since the current working directory may be a mounted filesystem, we
            # avoid the issue of not being able to unmount the filesystem at
            # shutdown time by changing it to the root directory.
            os.chdir(WORKDIR)
            # We probably don't want the file mode creation mask inherited from
            # the parent, so we give the child complete control over permissions.
            os.umask(UMASK)
        else:
            # exit() or _exit()?  See below.
            os._exit(0)  # Exit parent (the first child) of the second child.
    else:
        # exit() or _exit()?
        # _exit is like exit(), but it doesn't call any functions registered
        # with atexit (and on_exit) or any registered signal handlers.  It also
        # closes any open file descriptors.  Using exit() may cause all stdio
        # streams to be flushed twice and any temporary files may be unexpectedly
        # removed.  It's therefore recommended that child branches of a fork()
        # and the parent branch(es) of a daemon use _exit().
        os._exit(0)  # Exit parent of the first child.

    # NOTE(mrocha): Since we need all file descriptors opened during server
    # setup (i.e.: databases sessions, logging, socket connections, etc.), we
    # don't close them off after successfully forking the process

    # Close and redirect std file descriptors to /dev/null
    std_fileno = list(map(lambda s: s.fileno(), [sys.stdin, sys.stdout, sys.stderr]))
    null = os.open(REDIRECT_TO, os.O_RDWR)

    for fd in std_fileno:
        try:
            os.close(fd)
        except OSError:
            pass
        finally:
            os.dup2(null, fd)

    return 0


def start_server():
    logger.info('Running as a daemon')
    WORKDIR = FARADAY_BASE  # pylint:disable=unused-variable
    createDaemon()


def stop_server(port):
    """Stops Faraday Server if it isn't running"""
    pid = is_server_running(port)
    if pid is None:
        logger.error('Faraday Server is not running')
        return False

    try:
        logger.info(f'Sending SIGTERM to pid {pid}, in port {port}')
        os.kill(pid, signal.SIGTERM)
        logger.info("Faraday Server stopped successfully")
    except OSError as err:
        if err.errno == errno.EPERM:
            logger.error("Couldn't stop Faraday Server. User doesn't"
                         "have enough permissions")
            return False
        else:
            raise err

    remove_pid_file(port)
    return True


def is_server_running(port):
    """Returns server PID if it is running. Otherwise returns None"""
    pid = get_server_pid(port)
    if pid is None:
        return None

    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            remove_pid_file(port)
            return None
        elif err.errno == errno.EPERM:
            logger.warning("Server is running BUT the current user"
                           "doesn't have enough access to operate with it")
            return pid
        else:
            raise
    else:
        return pid


def get_server_pid(port):
    if not Path(str(FARADAY_SERVER_PID_FILE).format(port)).exists():
        return None

    with open(str(FARADAY_SERVER_PID_FILE).format(port), encoding='utf-8') as pid_file:
        # If PID file is badly written, delete it and
        # assume server is not running
        try:
            pid = int(pid_file.readline())
        except ValueError:
            logger.warning('PID file was found but is corrupted. '
                           'Assuming server is not running. Please check manually'
                           'if Faraday Server is effectively running')
            remove_pid_file(port)
            return None

    return pid


def create_pid_file(port):
    with open(str(FARADAY_SERVER_PID_FILE).format(port), 'w', encoding='utf-8') as pid_file:
        pid_file.write(f'{os.getpid()}')
    atexit.register(partial(remove_pid_file, port))


def remove_pid_file(port):
    os.remove(str(FARADAY_SERVER_PID_FILE).format(port))


def get_ports_running():
    ports = []
    home_dir = CONST_FARADAY_HOME_PATH

    for path in home_dir.iterdir():
        match = re.match(r"faraday\-server\-port\-(?P<last_name>[0-9]+)\.pid",
                         path.name)
        if match:
            ports.append(int(match.group(1)))

    return ports
