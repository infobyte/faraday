import requests
import argparse
import csv
import tempfile
import os
from couchdbkit import Server

def delete_cwe_db(couchdb_url):
    response = requests.delete(couchdb_url + "/cwe")
    if response.status_code == 200:
        print "[*] Deleted old CWE database: OK"
    else:
        print "[*] Deleted old CWE database failed:", response.text

def push_cwe(couchdb_url, filename):
    __serv = Server(uri=couchdb_url)

    workspace = __serv.get_or_create_db("cwe")

    with open(filename, 'r') as csvfile:
        cwereader = csv.reader(csvfile, delimiter=',')
        header = cwereader.next()
        print "[*] Beginning upload"
        for cwe in cwereader:
            cwe_doc = dict(zip(header, cwe))
            workspace.save_doc(cwe_doc)
        print "[*] Upload finished"

def delete_summary_csv(filename):

    dest_filename = filename + '~'
    with open(filename, "r") as source, open(dest_filename, "wb") as dest:
        reader = csv.DictReader(source)
        fieldnames = [f for f in reader.fieldnames if f != 'desc_summary']
        writer = csv.DictWriter(dest, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            if 'desc_summary' in row:
                row['description'] = row['desc_summary'] + '\n' + row.get('description', '')
                del row['desc_summary']
            writer.writerow(row)
    print dest_filename, filename
    os.rename(dest_filename, filename)
    print "[*] CSV converted OK"


def main():

    parser = argparse.ArgumentParser(prog='migrateCWEdatabase', epilog="Example: ./%(prog)s.py")

    parser.add_argument('-c', '--couchdburi', action='store', type=str,
                        dest='couchdb', default="http://127.0.0.1:5984",
                        help='Couchdb URL (default http://127.0.0.1:5984)')

    parser.add_argument('--convert-only', action="store_true",
                        help="Only convert the CSV file. Don't touch CouchDB")

    parser.add_argument('-f', '--csvfile', action='store', type=str,
                        dest='csvfile', default="data/cwe.csv",
                        help='CSV vulnerability template file '
                            '(default data/cwe.csv)')

    args = parser.parse_args()

    delete_summary_csv(args.csvfile)

    if not args.convert_only:
        delete_cwe_db(args.couchdb)
        push_cwe(args.couchdb, args.csvfile)

if __name__ == "__main__":
    main()
