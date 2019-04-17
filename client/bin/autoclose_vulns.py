#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''

import requests
from tqdm import tqdm
from dateutil import parser
from datetime import datetime

from faraday.client.persistence.server import models


__description__ = 'Closes vulns from the current workspace if a certain time has passed'
__prettyname__ = 'Close vulns if a certain time has passed'


def get_vulns_from_workspace(session, url, workspace):
    vulns = session.get('{url}/_api/v2/ws/{ws_name}/vulns/'\
                        .format(url=url, ws_name=workspace))

    return vulns.json()


def close_vulns(session, url, workspace, vulns, duration_time):
    vuln_closed_count = 0
    vulnerabilities = vulns['vulnerabilities']
    with tqdm(total=len(vulnerabilities)) as progress_bar:
        for vuln in vulnerabilities:
            create_time = vuln['value']['metadata']['create_time']

            # Convert date
            # create_time[:-6] -> date without timezone
            creation_date = parser.parse(create_time[:-6])
            elapsed_time = datetime.now() - creation_date

            # If elapsed time since creation is greater than duration time, the vuln will be closed
            if elapsed_time.total_seconds() > duration_time and vuln['value']['status'] != 'closed':
                vuln['value']['status'] = 'closed'
                close = session.put('{url}/_api/v2/ws/{ws_name}/vulns/{vuln_id}/'\
                                    .format(url=url,
                                            ws_name=workspace,
                                            vuln_id=vuln['id']
                                            ),
                                    json=vuln['value']
                                    )
                vuln_closed_count += 1
                progress_bar.update(1)

    return vuln_closed_count


def main(workspace='', args=None, parser=None):
    parser.add_argument('--vuln_duration',
                        help='Duration time of a vulnerability (in seconds)',
                        required=True)
    vuln_duration = parser.parse_args(args).vuln_duration

    s = requests.Session()

    url = models.server.SERVER_URL
    data = {
        "email": models.server.AUTH_USER,
        "password": models.server.AUTH_PASS
    }
    login_response = s.post('{url}/_api/login'.format(url=url), data=data)

    vulns = get_vulns_from_workspace(s, url, workspace)
    vulns_closed = close_vulns(s, url, workspace, vulns, float(vuln_duration))

    print "[+] {count} vulnerabilities closed in workspace '{ws}'".format(count=vulns_closed, ws=workspace)
    return 0, None
