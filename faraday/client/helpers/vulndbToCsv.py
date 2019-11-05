#!/usr/bin/env python3

"""
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
Author: Ezequiel Tavella

This script generate a CSV file with information about the vulndb database.
CSV Format:
cwe,name,desc_summary,description,resolution,exploitation,references
"""
from __future__ import  absolute_import
from __future__ import  print_function

from subprocess import call
from os import walk, path
import json
import csv
import re

URL_PROYECT = 'https://github.com/vulndb/data'
DB_PATH = './data/db/'


class JsonToCsv():

    def __init__(self, file):

        self.cwe = None
        self.name = None
        self.description = None
        self.resolution = None
        self.references = None
        self.severity = None

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
        self.severity = self.content.get('severity')
        # Reference to description file
        self.description = ''.join(self.content.get('description').get('$ref'))

        # Reference to fix file
        self.resolution = ''.join(self.content.get('fix').get('guidance').get('$ref'))

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
    print('[*]Execute git clone...')
    return_code = call(['git', 'clone', URL_PROYECT])

    if return_code != 0 and return_code != 128:
        print('[!]Error:\n Git return code: ' + str(return_code))

    #Get DB names...
    print('[*]Looking for DBs...')

    with open('vulndb.csv', mode='w') as file_csv:
        file_csv.write(
            'cwe,name,description,resolution,exploitation,references\n'
        )
        for (root, dirs, files) in walk(DB_PATH):
            if root == './data/db/en':
                vulndb_path = root
                vulndb_files = files
            elif root == './data/db/en/fix':
                # Folder /fix/ contains files with the resolution of every vuln
                fix_files = {
                    'path': root,
                    'filenames': parse_filenames(files)
                }
            elif root == './data/db/en/description':
                # Folder /description/ contains files with the description of every vuln
                desc_files = {
                    'path': root,
                    'filenames': parse_filenames(files)
                }

        writer = csv.writer(
            file_csv,
            quotechar = '"',
            delimiter = ',',
            quoting = csv.QUOTE_ALL
        )

        for file_db in vulndb_files:

            print('[*]Parsing ' + file_db)
            with open(path.join(vulndb_path, file_db), 'r') as file_object:
                csv_content = JsonToCsv(file_object)
                description = get_data_from_file(csv_content.description, desc_files)
                resolution = get_data_from_file(csv_content.resolution, fix_files)
                result = (
                    csv_content.cwe,
                    csv_content.name,
                    description,
                    resolution,
                    csv_content.severity,
                    ' '.join(csv_content.references or [])
                )

                writer.writerow(result)

        print('[*]Parse finished...')

def parse_filenames(files):
    # Parse filenames from description or fix folders
    files_dict = {}
    for filename in files:
        file_number = re.search('\d+', filename)
        if file_number:
            files_dict[file_number.group()] = filename
    return files_dict

def get_data_from_file(csv_content, files):
    # Get description or fix from the file reference parsed in JsonToCsv class
    data = ''
    number_from_file = re.search('\d+', csv_content)
    if not number_from_file:
        return data
    else:
        file_number = number_from_file.group()

    if file_number in files['filenames']:
        filename = files['filenames'][file_number]
    else:
        return data

    with open(path.join(files['path'], filename)) as file_object:
        data = file_object.read()

    return data

if __name__ == '__main__':
    main()

# I'm Py3