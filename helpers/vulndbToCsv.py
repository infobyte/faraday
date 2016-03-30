#!/usr/bin/env python2.7

'''
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
Author: Ezequiel Tavella
'''

'''
This script generate a CSV file with information about the vulndb database.
CSV Format:
cwe,name,desc_summary,description,resolution,exploitation,references

'''
from subprocess import call
from os import walk
import json
import csv

URL_PROYECT = 'https://github.com/vulndb/data'
DB_PATH = './data/db/'


class JsonToCsv():

    def __init__(self, file):

        self.cwe = None
        self.name = None
        self.description = None
        self.resolution = None
        self.references = None

        self.content = self.getContent(file)
        self.parse()

    def getContent(self, file):

        try:
            return json.load(file)
        except:
            return None

    def parse(self):

        """
        Available information of vulndb:
        cwe,name,description,resolution,references
        """

        if not self.content:
            return

        self.cwe = self.content.get('cwe')
        if self.cwe:
            self.cwe = self.cwe[0]

        self.name = self.content.get('title')
        self.description = ''.join(self.content.get('description'))
        self.resolution = ''.join(self.content.get('fix').get('guidance'))

        try:
            self.references = []
            for reference in self.content.get('references'):

                self.references.append(
                reference['title'] + ': ' + reference['url']
                )

        except:
            self.references = []


def main():

    #Get DB of vulndb
    print '[*]Execute git clone...'
    return_code = call(['git', 'clone', URL_PROYECT])

    if return_code != 0 and return_code != 128:
        print '[!]Error:\n Git return code: ' + str(return_code)

    #Get DB names...
    print '[*]Looking for DBs...'
    for (root, dirs, files) in walk(DB_PATH):

        file_csv = open('vulndb.csv','w')

        file_csv.write(
        'cwe,name,desc_summary,description,resolution,exploitation,references\n'
        )

        writer = csv.writer(
        file_csv,
        quotechar = '"',
        delimiter = ',',
        quoting = csv.QUOTE_ALL
        )

        for file_db in files:

            print '[*]Parsing ' + file_db
            with open(root + file_db, 'r') as file_object:

                csv_content = JsonToCsv(file_object)

                result = (
                csv_content.cwe,
                csv_content.name,
                '',
                csv_content.description,
                csv_content.resolution,
                '',
                ' '.join(csv_content.references)
                )

                writer.writerow(result)

        print '[*]Parse finished...'
        file_csv.close()

if __name__ == '__main__':
    main()
