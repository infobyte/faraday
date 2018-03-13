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


@mock.patch('os.path.isfile')
@mock.patch('os.remove')
@mock.patch('json.dump')
def test_gen_web_config(dump, remove, isfile):
    gen_web_config()
    assert isfile.called
    assert remove.called
    assert dump.called
    assert len(dump.call_args_list) == 1
    for call in dump.call_args_list:
        call[0][0] == {
                        'lic_db': 'faraday_licenses',
                        'osint': {u'host': u'shodan.io',
                        u'icon': u'shodan',
                        u'label': u'Shodan',
                        u'prefix': u'/search?query=',
                        u'suffix': u'',
                        u'use_external_icon': False},
                        'ver': '2.7.1',
                        'vuln_model_db': 'cwe'}

