'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import re
import random
import string
import tempfile
from pathlib import Path
from unittest import mock

from faraday import __version__

from faraday.server.config import (
    copy_default_config_to_local,
)


@mock.patch('shutil.copyfile')
def test_copy_default_config_to_local_does_not_exist(copyfile):
    random_name = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for _ in
        range(25)
    )
    filename = Path(tempfile.gettempdir()) / random_name

    with mock.patch('faraday.server.config.LOCAL_CONFIG_FILE', filename):
        assert copy_default_config_to_local() is None
        assert copyfile.called

    # the second call will re use the file just created.
    copyfile.reset_mock()
    assert copy_default_config_to_local() is None
    assert not copyfile.called


VERSION_PATTERN = r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?                           # epoch
        (?P<release>[0-9]+(?:\.[0-9]+)*)                  # release segment
        (?P<pre>                                          # pre-release
            [-_\.]?
            (?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>                                         # post release
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>                                          # dev release
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?       # local version
"""

_regex = re.compile(
    r"^\s*" + VERSION_PATTERN + r"\s*$",
    re.VERBOSE | re.IGNORECASE,
)


def isPEP440(arg):
    return not _regex.match(arg) is None


def test_exists_and_content():
    assert isPEP440(__version__)


def test_database_pool_defaults():
    from faraday.server.config import DatabaseConfigObject
    section = DatabaseConfigObject()
    assert section.pool_size == 5
    assert section.max_overflow == 15
    assert section.pool_timeout == 60
    assert section.pool_recycle == 1800


def test_database_pool_options_are_read_from_ini():
    from faraday.server.config import DatabaseConfigObject
    section = DatabaseConfigObject()
    section.parse({'pool_size': '3', 'max_overflow': '5', 'pool_timeout': '10', 'pool_recycle': '300'})
    assert (section.pool_size, section.max_overflow, section.pool_timeout, section.pool_recycle) == (3, 5, 10, 300)


def test_engine_options_use_database_pool_config():
    from faraday.server.app import get_engine_options
    with mock.patch('faraday.server.config.database.pool_size', 2), \
            mock.patch('faraday.server.config.database.max_overflow', 4), \
            mock.patch('faraday.server.config.database.pool_timeout', 15), \
            mock.patch('faraday.server.config.database.pool_recycle', 120):
        options = get_engine_options()
    assert options['pool_size'] == 2
    assert options['max_overflow'] == 4
    assert options['pool_timeout'] == 15
    assert options['pool_recycle'] == 120
    assert options['pool_pre_ping'] is True


def test_postgresql_engine_options_set_application_name_from_executable(monkeypatch):
    from faraday.server.app import get_engine_options
    monkeypatch.delenv('PGAPPNAME', raising=False)
    monkeypatch.setattr('sys.argv', ['/usr/local/bin/faraday-worker', '--queue', 'celery'])
    options = get_engine_options('postgresql+psycopg2://user:pass@localhost/faraday')
    assert options['connect_args'] == {'application_name': 'faraday-worker'}


def test_pgappname_takes_precedence_over_executable(monkeypatch):
    from faraday.server.app import get_engine_options
    monkeypatch.setenv('PGAPPNAME', 'faraday-cloud-web')
    monkeypatch.setattr('sys.argv', ['/usr/local/bin/faraday-server'])
    options = get_engine_options('postgresql+psycopg2://user:pass@localhost/faraday')
    assert options['connect_args'] == {'application_name': 'faraday-cloud-web'}


def test_application_name_is_truncated_to_postgresql_limit(monkeypatch):
    from faraday.server.app import get_engine_options
    monkeypatch.setenv('PGAPPNAME', 'x' * 100)
    options = get_engine_options('postgresql+psycopg2://user:pass@localhost/faraday')
    assert options['connect_args']['application_name'] == 'x' * 63


def test_sqlite_engine_options_have_no_application_name():
    from faraday.server.app import get_engine_options
    options = get_engine_options('sqlite:////tmp/faraday.db')
    assert 'connect_args' not in options
