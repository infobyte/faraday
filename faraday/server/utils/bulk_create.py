"""
Faraday Penetration Test IDE
Copyright (C) 2020  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging

logger = logging.getLogger(__name__)


def add_creator(data, creator_user):
    hosts_ = []
    for host in data["hosts"]:
        host["creator_id"] = creator_user.id
        for service in host["services"]:
            service["creator_id"] = creator_user.id
            for vuln in service["vulnerabilities"]:
                vuln["creator_id"] = creator_user.id
        for vuln in host["vulnerabilities"]:
            vuln["creator_id"] = creator_user.id
        for cred in host["credentials"]:
            cred["creator_id"] = creator_user.id
        hosts_.append(host)

    response = {'hosts': hosts_}
    if "command" in data:
        command = data['command']
        command["creator_id"] = creator_user.id
        response["command"] = command

    return response
