#!/usr/bin/env python2.7

'''
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
Author: Ezequiel Tavella

This script generate a CSV file with information about the cfdb database.
CSV Format:
cwe,name,description,resolution,exploitation,references
'''

from subprocess import call
from os import walk
import csv

URL_PROYECT = 'https://github.com/mubix/cfdb'
DB_PATH = './cfdb/'

class parseFile():

    def __init__(self, file_md):

        self.cwe = ''
        self.name = None
        self.description = None
        self.resolution = None
        self.explotation = None
        self.references = None

        self.file = file_md
        self.parse()

    def getContent(self):

        result = []
        while True:

            subLine = self.file.readline().strip('\n\r')
            if subLine != '\n':
                #If EOF -> break
                if subLine == '' :
                    break

                if not subLine.startswith('##') :
                    result.append(subLine)
                else:
                    break

        return ''.join(result)

    def parse(self):

        line = self.file.readline()
        while line != '':

            title = line.startswith('Title: ')
            description = line.startswith('Description: ')
            resolution = line.startswith('## Remediation')
            references = line.startswith('## References')
            explotation = line.startswith('## Exploitation')

            #Slice title... read line and continue with other line
            if title:

                self.name = line[title + 6:].strip('\n\r')
                line = self.file.readline()
                continue

            #Read first line with \n and read the content
            elif description:
                line = self.file.readline()
                self.description = self.getContent()
            elif resolution:
                line = self.file.readline()
                self.resolution = self.getContent()
            elif references:
                line = self.file.readline()
                self.references = self.getContent()
            elif explotation:
                line = self.file.readline()
                self.explotation = self.getContent()
            #Nothing here...read line
            else:
                line = self.file.readline()


def main():

    #Get DB cfdb
    print '[*]Execute git clone...'
    return_code = call(['git', 'clone', URL_PROYECT])

    if return_code != 0 and return_code != 128:
        print '[!]Error:\n Git return code: ' + str(return_code)

    file_csv = open('cfdb.csv','w')

    file_csv.write(
    'cwe,name,description,resolution,exploitation,references\n'
    )

    #CSV Writer
    writer = csv.writer(
    file_csv,
    quotechar = '"',
    delimiter = ',',
    quoting = csv.QUOTE_ALL
    )

    #Get DB names...
    print '[*]Looking for DBs...'
    for (root, dirs, files) in walk(DB_PATH):

        #Jump dirs without info
        if root.find('.git') < 0 and root.find('.gitignore') < 0:
            if root != './cfdb/':

                print '[*]Parsing folder: ' + root
                for file_db in files:

                    print '[_]File: ' + root + '/' + file_db
                    with open(root + '/' + file_db, 'r') as file_md:

                        csv_content = parseFile(file_md)

                        result = (
                        csv_content.cwe,
                        csv_content.name,
                        csv_content.description,
                        csv_content.resolution,
                        csv_content.explotation,
                        csv_content.references
                        )

                        writer.writerow(result)

                print '[*]Parse folder finished...\n'

    print '[*]All Finished... OK'

    file_csv.close()

if __name__ == '__main__':
    main()
