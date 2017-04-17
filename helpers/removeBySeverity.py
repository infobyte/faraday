#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

This script removes vulnerabilities from Couch depending on thei severity. 
'''

import argparse
import json
import requests
import os

def main():
    #arguments parser
    parser = argparse.ArgumentParser(prog='removeBySeverity', epilog="Example: ./%(prog)s.py")
    parser.add_argument('-c', '--couchdburi', action='store', type=str,
                        dest='couchdb',default="http://127.0.0.1:5984",
                        help='Couchdb URL as http://user:password@couch_ip:couch_port (defaults to http://127.0.0.1:5984)')
    parser.add_argument('-d', '--db', action='store', type=str, required=True,
                        dest='db', help='DB to process')
    parser.add_argument('-s', '--severity', action='store', type=str, required=True,
                        dest='severity', help='Vulnerability severity')
    parser.add_argument('-t', '--test', action='store_true', 
                        dest='test', help='Dry run, does everything except updating the DB')
    parser.add_argument('-v', '--verbose', action='store_true', 
                        dest='verbose', help='Extended output')

    #arguments put in variables
    args = parser.parse_args()
    db = args.db
    severity = args.severity
    test = args.test
    verbose = args.verbose

    #default value from ENV COUCHDB
    couchdb = os.environ.get('COUCHDB')
    #Else from argument
    if not couchdb:
        couchdb = args.couchdb

    fixDb(couchdb, db, severity, test, verbose)

def fixDb(couchdb, db, severity, test, verbose):
    couchdb = str(couchdb)
    db = str(db)

    #get all broken elements from CouchDB
    headers = {'Content-Type': 'application/json'}
    payload = { "map" : """function(doc) { if((doc.type == \"Vulnerability\" && doc.severity == \""""+severity+"""\") ||
                                            (doc.type == \"VulnerabilityWeb\" && doc.severity == \""""+severity+"""\")){ emit(doc._id, doc._rev); }}""" }

    r = requests.post(couchdb + '/' + db + '/_temp_view', headers=headers, data=json.dumps(payload))
    response_code = r.status_code

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
                if verbose:
                    print " - Deleting vulnerability with ID " + id
                if not test:
                    delete = requests.delete(couchdb + '/' + db + '/' + id + '?rev=' + rev)
                    if verbose:
                        print " -- " + delete.reason + " (" + str(delete.status_code) + ")"
            print " Done"
        else:
            print "No vulns were found in DB " + db + " with severity " + severity + "!"
    elif response_code == 401:
        print " Autorization required to access " + db + ", make sure to add user:pwd to Couch URI using --couchdburi"
    else:
        print "Error connecting to CouchDB, please verify the service is up"

if __name__ == "__main__":
    main()
