import os
import time
import signal
import subprocess
from datetime import datetime


def test_start_and_kill_faraday_server():
    """
        Starts the server and then send a signal to kill the
        process gracefully.
        The idea is to catch a broken faraday-server.py
        After sending the signal we wait for 15 seconds and
        if the server didn't stop we fail the test also.
    """
    current_path = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(current_path, '..', 'faraday-server.py')
    command = ['/usr/bin/env', 'python2.7', server_script]
    subproc = subprocess.Popen(command)

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

    assert subproc.returncode == 0
