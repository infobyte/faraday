'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import random
import string
import mock

from server.config import (
    copy_default_config_to_local,
    gen_web_config
)


@mock.patch('os.makedirs')
@mock.patch('shutil.copyfile')
def test_copy_default_config_to_local_does_not_exist(copyfile, makedirs):
    random_name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in
            range(25))

    new_file = '/tmp/{0}'.format(random_name)
    with mock.patch('server.config.LOCAL_CONFIG_FILE', new_file):
        assert copy_default_config_to_local() is None
        assert makedirs.called
        assert copyfile.called

    # the second call will re use the file just created.
    makedirs.reset_mock()
    copyfile.reset_mock()
    assert copy_default_config_to_local() is None
    assert not makedirs.called
    assert not copyfile.called
