import os
import subprocess
from faraday.server.config import FARADAY_BASE

try:
    import ConfigParser
except ImportError:
    import faraday.client.configparser as ConfigParser


def test_manage_migrate():
    """
        Run manage migrate with nothing to migrate
        The idea is to catch a broken migration
    """
    if 'POSTGRES_DB' in os.environ:
        # I'm on gitlab ci runner

        command = ['faraday-manage', 'migrate']
        subproc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=FARADAY_BASE) # TODO THIS SHOULD FIXED AND THEN REMOVED ISSUE 5570
        subproc.wait()
        std, err = subproc.communicate()
        assert subproc.returncode == 0, ('Create tables failed!', std, err)
