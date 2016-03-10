#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
'''
import os

def getCweData():

    import requests
    import json

    #Get elements from cwe DB in couchdb
    headers = {'Content-Type': 'application/json'}

    payload = {
    'map' :
    'function(doc) { if(doc.severity && doc.name){'
    'emit(doc.name, doc.severity); }}'
    }

    r = requests.post(
    couchdb + '/cwe/_temp_view',
    headers = headers,
    data = json.dumps(payload)
    )

    response_code = r.status_code

    if response_code == 200:

        data = r.json()['rows']
        dict = {}

        for item in data:

            value = item['value']
            if value == 'informational':
                value = 'info'

            dict.update( {item['key'] : value} )

        return dict

    elif response_code == 401:
        print 'Autorization required, make sure to add user:pwd to Couch URI'
    else:
        print 'Error couchDB: ' + str(response_code) + str(r.text)


def checkSeverity(vuln, cwe_dict, severity_choose, workspace):

    import requests
    import json

    severity_dict = {
    'unclassified' : 0,
    'info' : 1,
    'low' : 2,
    'med' : 3,
    'high' : 4,
    'critical' : 5,
    'all' : 100
    }

    if vuln._name in cwe_dict and severity_dict[vuln.severity] <= severity_dict[severity_choose] :

        print 'Change: ' + vuln._name + ' to ' + cwe_dict[vuln._name]

        #Get object Vuln
        response = requests.get(
        couchdb + '/' + workspace + '/' + str (vuln._id)
        )
        vulnWeb = response.json()

        #Change severity
        vulnWeb['severity'] = cwe_dict[vuln._name]

        #Put changes...
        headers = {'Content-Type': 'application/json'}
        update = requests.put(
        couchdb + '/' + workspace + '/' + vuln._id,
        headers = headers,
        data = json.dumps(vulnWeb)
        )

        if update.status_code == 200 or update.status_code == 201:
            print 'Change OK\n'
        else:
            print 'Error in update Vulnerability, status code: ' + str(update.status_code)
            print update.text

# Main
list_parameters = script_parameters.split(' ')

#default value from ENV COUCHDB
global couchdb
couchdb = os.environ.get('COUCHDB')

if not couchdb and list_parameters[1]:
    couchdb = list_parameters[1]

#Default workspace
workspace = 'untitled'
if list_parameters[2]:
    workspace = list_parameters[2]

#Default severity
severity = 'info'
if list_parameters[0]:
    severity = list_parameters[0]

help = (
'\nGet Vulns filtered by Severity and change Severity based in CWE\n'
'Parameters:\n'
'1º : Filter by Severity (<=) (unclassified, info, low, med, high, critical, all)\n'
'2º : Url to Couchdb\n'
'3º : Workspace name\n'
'Example:'
'./fplugin.py -f getSeverityByCwe.py -p high '
'http://username:password@localhost:5984/ workspace_test_name'
)

if script_parameters == '' or script_parameters == None :
    print help
    raise(Exception('Exit for help'))

cwe = getCweData()

for host in api.__model_controller.getAllHosts():
    for v in host.getVulns():
        checkSeverity(v, cwe, severity, workspace)

    for i in host.getAllInterfaces():
        for s in i.getAllServices():
            for v in s.getVulns():
                checkSeverity(v, cwe, severity, workspace)
