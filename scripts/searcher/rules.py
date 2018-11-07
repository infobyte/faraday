#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
## Faraday Penetration Test IDE
## Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###


threshold = 0.75
min_weight = 0.3

rules = [
    {
        'id': 'PARENT_TEST',
        'model': 'Vulnerability',
        'parent': '192.168.1.18',
        'object': "regex=^generic-",
        'conditions': ["severity=info"],
        'actions': ["--UPDATE:severity=critical"]
    },
    {
        'id': 'CIFRADO_DEBIL',
        'model': 'Vulnerability',
        'object': "name=EN-Cifrado%Débil%(SSL%weak%ciphers)",
        'actions': ["--UPDATE:severity=info"]
    },

    {
        'id': 'CLIENT_TEST',
        'model': 'Vulnerability',
        'parent': '50.56.220.123',
        'object': "regex=^Device",
        'conditions': ["severity=info", "creator=Nessus regex=^OS"],
        'actions': ["--UPDATE:severity=critical", "--UPDATE:confirmed=True"]
    },

    {
        'id': 'CLIENT_TEST_2',
        'model': 'Vulnerability',
        'parent': 'http',
        'object': "regex=Email target=200.58.121.156",
        'conditions': ["severity=info", "creator=Burp"],
        'actions': ["--UPDATE:severity=med", "--UPDATE:confirmed=True"]
    },

    {
        'id': 'CLIENT_TEST_3',
        'model': 'Vulnerability',
        'parent': '320131ea90e3986c8221291c683d6d19bfe8503b',
        'object': "creator=Nessus --old",
        'conditions': ["severity=info", "creator=Nessus"],
        'actions': ["--UPDATE:refs=VCritical", "--UPDATE:confirmed=True"]
    },

    {
        'id': 'CU1',
        'model': 'Vulnerability',
        'parent': '50.56.220.123',
        'object': "severity=critical",
        'actions': ["--UPDATE:severity=info"]
    },

    {
        'id': 'CU2',
        'model': 'Vulnerability',
        'parent': '50.56.220.123',
        'object': "severity=info confirmed=True",
        'actions': ["--EXECUTE:ls"]
    },

    {
        'id': 'CU3A',
        'model': 'Vulnerability',
        'fields': ['name'],
        'actions': ["--UPDATE:confirmed=False"]
    },

    {
        'id': 'CU3B',
        'model': 'Vulnerability',
        'fields': ['name'],
        'object': "--old",
        'actions': ["--UPDATE:confirmed=True"]
    },

    {
        'id': 'CU4',
        'model': 'Vulnerability',
        'object': "name=Email%addresses%disclosed creator=Burp",
        'actions': ["--UPDATE:refs=RefsX"]
    },

    {
        'id': 'CU4B',
        'model': 'Vulnerability',
        'object': "name=Email%addresses%disclosed creator=Burp",
        'actions': ["--UPDATE:-refs=RefsY"]
    },

    {
        'id': 'CU5',
        'model': 'Vulnerability',
        'object': "name=OS%Identification",
        'actions': ["--UPDATE:template=445"]
    },

    {
        'id': 'CU5B1',
        'model': 'Vulnerability',
        'object': "severity=critical",
        'actions': ["--UPDATE:template=EN-Cifrado Debil (SSL weak ciphers)"]
    },

    {
        'id': 'CU5B',
        'model': 'Vulnerability',
        'object': "severity=critical",
        'actions': ["--UPDATE:template=EN-Cifrado Debil (SSL weak ciphers)"]
    },
    {
        'id': 'CU6',
        'model': 'Service',
        'object': "name=http",
        'actions': ["--UPDATE:owned=True"]
    },
    {
        'id': 'CU6B',
        'model': 'Service',
        'fields': ['name'],
        'actions': ["--UPDATE:description=SET BY RULE"]
    },

    {
        'id': 'CU7',
        'model': 'Host',
        'object': "name=172.16.138.1",
        'actions': ["--DELETE:"]
    },

    {
        'id': 'CU7B',
        'model': 'Host',
        'fields': ['name'],
        'actions': ["--UPDATE:owned=True"]
    }

]
