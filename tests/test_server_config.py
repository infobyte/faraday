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
