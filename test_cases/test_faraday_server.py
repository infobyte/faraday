import os
import time
import signal
import subprocess
from datetime import datetime
from server.utils import daemonize
import server.config

try:
    import ConfigParser
except ImportError:
    import configparser as ConfigParser


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

    if 'POSTGRES_DB' in os.environ:
        # I'm on gitlab ci runner
        # I will overwrite server.ini
        connection_string = 'postgresql+psycopg2://{username}:{password}@postgres/{database}'.format(
            username=os.environ['POSTGRES_USER'],
            password=os.environ['POSTGRES_PASSWORD'],
            database=os.environ['POSTGRES_DB'],
        )
        faraday_config = ConfigParser.SafeConfigParser()
        config_path = os.path.expanduser('~/.faraday/config/server.ini')
        faraday_config.read(config_path)
        try:
            faraday_config.add_section('database')
        except ConfigParser.DuplicateSectionError:
            pass
        faraday_config.set('database', 'connection_string', connection_string)
        with open(config_path, 'w') as faraday_config_file:
            faraday_config.write(faraday_config_file)
        manage_script = os.path.join(current_path, '..', 'manage.py')
        command = ['/usr/bin/env', 'python2.7', manage_script, 'create-tables']
        subproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd= os.path.join(current_path, '..'))
        subproc.wait()
        std, err = subproc.communicate()
        assert subproc.returncode == 0, ('Create tables failed!', std, err)

    server_script = os.path.join(current_path, '..', 'faraday-server.py')
    command = ['/usr/bin/env', 'python2.7', server_script, '--port', '{0}'.format(server_port), '--debug']
    subproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    start = datetime.now()
    while subproc.returncode is None:
        now = datetime.now()
        delta = now - start
        if delta.seconds > 140:
            raise UserWarning('Faraday server test timeout!')
        if delta.seconds > 30:
            subproc.send_signal(signal.SIGTERM)
            subproc.wait()
        subproc.poll()
        delta = now - start
        subproc.poll()
        time.sleep(0.1)
    out, err = subproc.communicate()
    if subproc.returncode != 0:
        log_path = os.path.expanduser('~/.faraday/logs/faraday-server.log')
        with open(log_path, 'r') as log_file:
            print(log_file.read())
    assert subproc.returncode == 0, (out, err, command, server_script)
