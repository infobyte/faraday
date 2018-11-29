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
    }
]
