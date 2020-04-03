# Faraday Penetration Test IDE
# Copyright (C) 2020  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import logging

logger = logging.getLogger(__name__)


def add_creator(vuln_data, creator_user):
    for host in vuln_data["hosts"]:
        host["creator_id"] = creator_user.id
        for service in host["services"]:
            service["creator_id"] = creator_user.id
        for vuln in host["vulnerabilities"]:
            vuln["creator_id"] = creator_user.id
        for cred in host["credentials"]:
            cred["creator_id"] = creator_user.id

    return vuln_data
