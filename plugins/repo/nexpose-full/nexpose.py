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

def parse_html_type(node):
    ret = ""
    tag = node.tag.lower()

    if tag == 'containerblockelement':
        if len(list(node)) > 0:
            for child in list(node):
                ret += parse_html_type(child)
        else:
            ret += str(node.text).strip()
    if tag == 'listitem':
        ret = str(node.text).strip()
    if tag == 'orderedlist':
        i = 1
        for item in list(node):
            ret += "\t" + str(i) + " " + parse_html_type(item) + "\n"
            i += 1
    if tag == 'paragraph':
        if len(list(node)) > 0:
            for child in list(node):
                ret += parse_html_type(child)
        else:
            ret += str(node.text).strip()
    if tag == 'unorderedlist':
        for item in list(node):
            ret += "\t" + "* " + parse_html_type(item) + "\n"
    if tag == 'urllink':
        if node.text:
            ret += str(node.text).strip() + " "
        last = ""
        for attr in node.attrib:
            if node.get(attr) != node.get(last):
                ret += str(node.get(attr)) + " "
            last = attr
        
    return ret

def parse_tests_type(node, vulnsDefinitions):
    vulns = list()

    for tests in node.iter('tests'):
        for test in tests.iter('test'):
            vuln = dict()
            if test.get('id').lower() in vulnsDefinitions:
                vuln = vulnsDefinitions[test.get('id').lower()]
                for desc in list(test):
                    vuln['desc'] += parse_html_type(desc)
                vulns.append(vuln)

    return vulns

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
                vuln['desc'] = parse_html_type(item)
            if item.tag == 'exploits':
                for exploit in list(item):
                    vuln['refs'].append(str(exploit.get('title')).strip() + ' ' + str(exploit.get('link')).strip())
            if item.tag == 'references':
                for ref in list(item):
                    vuln['refs'].append(str(ref.text).strip())
            if item.tag == 'solution':
                vuln['resolution'] = parse_html_type(item)
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
        host['name'] = node.get('address')
        host['hostnames'] = set()
        host['services'] = list()
        host['vulns'] = parse_tests_type(node, vulns)

        for names in node.iter('names'):
            for name in list(names):
                host['hostnames'].add(name.text)

        for endpoints in node.iter('endpoints'):
            for endpoint in list(endpoints):
                svc = {
                    'protocol': endpoint.get('protocol'),
                    'port': endpoint.get('port'),
                    'status': endpoint.get('status'),
                }
                for services in endpoint.iter('services'):
                    for service in list(services):
                        svc['name'] = service.get('name')
                        svc['vulns'] = parse_tests_type(service, vulns)
                        for configs in service.iter('configurations'):
                            for config in list(configs):
                                if "banner" in config.get('name'):
                                    svc['version'] = config.get('name')

                host['services'].append(svc)

        hosts.append(host)
