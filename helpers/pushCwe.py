#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
'''
This script upload a Vulnerability database to Couch.
It takes the content of the DB from data/cwe.csv
'''
import argparse
import os
from couchdbkit import Server, designer
import json
import csv


def main():

    #arguments parser
    parser = argparse.ArgumentParser(prog='pushExecutiveReports', epilog="Example: ./%(prog)s.py")
    parser.add_argument('-c', '--couchdburi', action='store', type=str,
                        dest='couchdb',default="http://127.0.0.1:5984",
                        help='Couchdb URL (default http://127.0.0.1:5984)')

    #arguments put in variables
    args = parser.parse_args()

    #default value from ENV COUCHDB
    couchdb = os.environ.get('COUCHDB')
    #Else from argument
    if not couchdb:
        couchdb = args.couchdb
    __serv = Server(uri = couchdb)

    # reports = os.path.join(os.getcwd(), "views", "reports")
    workspace = __serv.get_or_create_db("cwe")
    # designer.push(reports, workspace, atomic = False)

    with open('data/cwe.csv', 'r') as csvfile:
        cwereader = csv.reader(csvfile, delimiter=',')
        header = cwereader.next()
        for cwe in cwereader:
            cwe_doc = dict(zip(header, cwe))
            workspace.save_doc(cwe_doc)

if __name__ == "__main__":
    main()
