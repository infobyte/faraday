'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

try:
    from lxml import etree as ET
except ImportError:
    import xml.etree.ElementTree as ET

from server.config import FARADAY_BASE


def test_matching_versions():
    with open(FARADAY_BASE + '/VERSION', 'r') as output:
        version_file = output.read().strip()

    version_default = parse_element_from_xml('version')

    assert version_file == version_default


def parse_element_from_xml(tag_name):
    with open(FARADAY_BASE + '/config/default.xml', 'r') as output:
        default_data = output.read()
    tree = ET.fromstring(default_data)
    default_element = tree.find(tag_name).text

    return default_element
