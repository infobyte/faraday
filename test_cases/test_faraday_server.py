import os
import time
import signal
import subprocess
from datetime import datetime
from server.utils import daemonize


def test_start_and_kill_faraday_server():
    """
        Starts the server and then send a signal to kill the
        process gracefully.
        The idea is to catch a broken faraday-server.py
        After sending the signal we wait for 15 seconds and
        if the server didn't stop we fail the test also.
    """
    current_path = os.path.dirname(os.path.abspath(__file__))
    server_port = 5988
    while daemonize.is_server_running(server_port) and server_port < 6500:
        server_port += 1

    if server_port > 6500:
        raise Exception('No free ports could be found')

    server_script = os.path.join(current_path, '..', 'faraday-server.py')
    command = ['/usr/bin/env', 'python2.7', server_script, '--port', '{0}'.format(server_port)]
    subproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    start = datetime.now()
    while subproc.returncode is None:
        now = datetime.now()
        delta = now - start
        if delta.seconds > 40:
            raise UserWarning('Faraday server test timeout!')
        if delta.seconds > 4:
            subproc.send_signal(signal.SIGTERM)
            subproc.wait()
        subproc.poll()
        delta = now - start
        subproc.poll()
        time.sleep(0.1)
    out, err = subproc.communicate()
    assert subproc.returncode == 0, err
