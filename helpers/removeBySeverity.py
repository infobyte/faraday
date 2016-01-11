#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
'''
This script either updates or removes Interfaces, Services and Vulnerabilities in case their parent property is null.
If the property is null but a parent is found in Couch, the document is updated.
If the parent is not found in Couch the document is deleted, since it is an invalid one.
'''

import argparse
import json
import requests
import os
from pprint import pprint

def main():
    #arguments parser
    parser = argparse.ArgumentParser(prog='removeBySeverity', epilog="Example: ./%(prog)s.py")
    parser.add_argument('-c', '--couchdburi', action='store', type=str,
                        dest='couchdb',default="http://127.0.0.1:5984",
                        help='Couchdb URL (default http://127.0.0.1:5984)')
    parser.add_argument('-d', '--db', action='store', type=str,
                        dest='db', help='DB to process')
    parser.add_argument('-s', '--severity', action='store', type=str,
                        dest='severity', help='Vulnerability severity')

    #arguments put in variables
    args = parser.parse_args()
    dbs = list()
    severity = args.severity

    #default value from ENV COUCHDB
    couchdb = os.environ.get('COUCHDB')
    #Else from argument
    if not couchdb:
        couchdb = args.couchdb

    if args.db:
        dbs.append(args.db)

    if len(dbs) == 0:
        dbs = requests.get(couchdb + '/_all_dbs')
        dbs = dbs.json()
        dbs = filter(lambda x: not x.startswith('_') and x != 'cwe' and x != 'reports', dbs)
    
    for db in dbs:
        fixDb(couchdb, db, severity)

def fixDb(couchdb, db, severity):
    couchdb = str(couchdb)
    db = str(db)

    #get all broken elements from CouchDB
    headers = {'Content-Type': 'application/json'}
    payload = { "map" : """function(doc) { if((doc.type == \"Vulnerability\" && doc.severity == \""""+severity+"""\") ||
                                            (doc.type == \"VulnerabilityWeb\" && doc.severity == \""""+severity+"""\")){ emit(doc._id, doc._rev); }}""" }

    print payload
    r = requests.post(couchdb + '/' + db + '/_temp_view', headers=headers, data=json.dumps(payload))
    response_code = r.status_code

    print response_code
    if response_code == 200:
        response = r.json()
        rows = response['rows']
        # ID is ID, value is REV

        if len(rows) > 0:
            print " [*[ Processing " + str(len(rows)) + " documents for " + db + " ]*]"

            for row in rows:
                id = str(row['id'])
                rev = str(row['value'])

                # delete vuln
                print " - Deleting vulnerability \"" + child['name'] + "\"  with ID " + id
                delete = requests.delete(couchdb + '/' + db + '/' + id + '?rev=' + rev)
                print " -- " + delete.reason + " (" + str(delete.status_code) + ")"
        else:
            print "No vulns were found in DB " + db + " with severity " + severity + "!"
        """
    elif response_code == 401:
        print " Autorization required to access " + db + ", make sure to add user:pwd to Couch URI using --couchdburi"

if __name__ == "__main__":
    main()
