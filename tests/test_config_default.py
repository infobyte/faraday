'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from __future__ import absolute_import

try:
    from lxml import etree as ET
except ImportError:
    import xml.etree.ElementTree as ET

import os

from faraday import __version__ as faraday_version
from faraday.server.config import FARADAY_BASE


def test_matching_versions():
    version_default = parse_element_from_xml('version')

    assert faraday_version == version_default


def parse_element_from_xml(tag_name):
    with open(os.path.join(FARADAY_BASE, 'config/default.xml'), 'r') as output:
        default_data = output.read()
    tree = ET.fromstring(default_data)
    default_element = tree.find(tag_name).text

    return default_element


# I'm Py3
