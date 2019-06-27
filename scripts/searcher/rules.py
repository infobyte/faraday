#!/usr/bin/env python
# -*- coding: utf-8 -*-

###
## Faraday Penetration Test IDE
## Copyright (C) 2018  Infobyte LLC (http://www.infobytesec.com/)
## See the file 'doc/LICENSE' for the license information
###


threshold = 0.75
min_weight = 0.3

"""
    APPLY_MS_REFS adds 
    'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010' 
    as refs to all vulnerabilities which name begins with 'MS17-010' 
    and its creator is 'Nessus'. 
"""

rules = [
    {
        'id': 'APPLY_MS_REFS',
        'model': 'Vulnerability',
        'object': "regex=^MS17-010",
        'conditions': ["creator=Nessus"],
        'actions': ["--UPDATE:refs=https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010"]
    },

    {
        'id': 'APPLY_MS_REFS_{{id}}',
        'model': 'Vulnerability',
        'object': "regex=^{{tag}}",
        'conditions': ["creator=Nessus"],
        'actions': ["--UPDATE:refs=https://docs.microsoft.com/en-us/security-updates/securitybulletins/{{year}}/{{tag}}"],
        'values': [{'tag': 'ms17-010', 'year': '2017', 'id': 'DYNAMIC'}, {'tag': 'ms18-010', 'year': '2018', 'id': 'DYNAMIC'}]
    },

    {
        'id': 'APPLY_REFS_ACCORDING_SEVERITY_{{sev}}',
        'model': 'Vulnerability',
        'object': "severity={{sev}}",
        'actions': ["--UPDATE:refs=https://docs.microsoft.com/en-us/security-updates/securitybulletins/{{year}}/{{tag}}"],
        'values': [{'tag': 'ms17-010', 'year': '2017', 'sev': 'low'}, {'tag': 'ms18-010', 'year': '2018', 'sev': 'med'}]
    }
]
# I'm Py3