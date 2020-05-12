import faraday.server.config
from faraday.server.models import (
    Host,
    Service,
    Workspace,
    VulnerabilityWeb,
)

import sys
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


def change_vulns(affected_vulns, workspace):
    vulns_id = []
    for vuln in affected_vulns:
        assert vuln.service_id == None and vuln.type == 'vulnerability_web'
        session.execute(text("""
            UPDATE vulnerability SET type=\'vulnerability\' where id= :affected_vuln_id ;
        """), {'affected_vuln_id': vuln.id})

        vulns_id.append(vuln.id)
        session.commit()

    print("[+] {vulns_length} vulnerabilities changed in workspace named {ws_name}"
           .format(vulns_length=len(affected_vulns),
                   ws_name=workspace.name))
    print("    Vulnerabilities ID: {ids}".format(ids=vulns_id))


conn_string = faraday.server.config.database.connection_string
engine = create_engine(conn_string)
Session = sessionmaker(bind=engine)
session = Session()

workspaces = session.query(Workspace)

log_file = 'fix_vulnweb_without_service_logs.log'
with open(log_file, 'a') as log:
    date_executed = 'Script executed at {}\n'.format(datetime.now().strftime("%m-%d-%Y %H:%M"))
    log.write(date_executed)

    # Redirect prints to log file
    orig_stdout = sys.stdout
    sys.stdout = log

    for ws in workspaces.all():
        vulns_web = session.query(VulnerabilityWeb).filter_by(workspace_id=ws.id, service_id=None)
        if vulns_web.all():
            change_vulns(vulns_web.all(), ws)
        else:
            print("[-] No vulnerabilities to change in workspace named {ws_name}".format(ws_name=ws.name))

    sys.stdout = orig_stdout

# Print log file
with open(log_file, 'r') as log:
    print(log.read())

print("Logs saved in file named {}".format(log_file))
# I'm Py3