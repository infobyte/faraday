#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import with_statement
import re
import os
import pprint
import sys

try:
    import xml.etree.cElementTree as ET
    import xml.etree.ElementTree as ET_ORIG
    ETREE_VERSION = ET_ORIG.VERSION
except ImportError:
    import xml.etree.ElementTree as ET
    ETREE_VERSION = ET.VERSION
                      
ETREE_VERSION = [int(i) for i in ETREE_VERSION.split(".")]

def htmlType(node):
    ret = ""
    tag = node.tag.lower()

    if tag == 'containerblockelement':
        if len(list(node)) > 0:
            for child in list(node):
                ret += htmlType(child)
        else:
            ret += str(node.text).strip()
    if tag == 'listitem':
        ret = str(node.text).strip()
    if tag == 'orderedlist':
        i = 1
        for item in list(node):
            ret += "\t" + str(i) + " " + htmlType(item) + "\n"
            i += 1
    if tag == 'paragraph':
        if len(list(node)) > 0:
            for child in list(node):
                ret += htmlType(child)
        else:
            ret += str(node.text).strip()
    if tag == 'unorderedlist':
        for item in list(node):
            ret += "\t" + "* " + htmlType(item) + "\n"
    if tag == 'urllink':
        if node.text:
            ret += str(node.text).strip() + " "
        last = ""
        for attr in node.attrib:
            if node.get(attr) != node.get(last):
                ret += str(node.get(attr)) + " "
            last = attr
        
    return ret

current_path = os.path.abspath(os.getcwd())

inputfile = sys.argv[1]

tree = ET.parse(inputfile)

root = tree.getroot()

vulns = dict()
hosts = list()

for vulnsDef in root.iter('VulnerabilityDefinitions'):
    for vulnDef in vulnsDef.iter('vulnerability'):
        vid = vulnDef.get('id').lower()
        vector = vulnDef.get('cvssVector')

        vuln = {
            'desc': "",
            'name': vulnDef.get('title'),
            'refs': [ "vector: " + vector, vid],
            'resolution': "",
            'severity': (int(vulnDef.get('severity'))-1)/2,
            'tags': list()
        }

        for item in list(vulnDef):
            if item.tag == 'description':
                vuln['desc'] = htmlType(item)
            if item.tag == 'exploits':
                for exploit in list(item):
                    vuln['refs'].append(str(exploit.get('title')).strip() + ' ' + str(exploit.get('link')).strip())
            if item.tag == 'references':
                for ref in list(item):
                    vuln['refs'].append(str(ref.text).strip())
            if item.tag == 'solution':
                vuln['resolution'] = htmlType(item)
            """
            # there is currently no method to register tags in vulns
            if item.tag == 'tags':
                for tag in list(item):
                    vuln['tags'].append(tag.text.lower())
            """
        vulns[vid] = vuln

for nodes in root.iter('nodes'):
    for node in nodes.iter('node'):
        host = dict()
        for tests in node.iter('tests'):
            host['vulns'] = list()
            for test in tests.iter('test'):
                vuln = dict()
                if test.get('id').lower() in vulns:
                    vuln = vulns[test.get('id').lower()]
                    for desc in list(test):
                        vuln['desc'] += htmlType(desc)
                    host['vulns'].append(vuln)
        hosts.append(host)
