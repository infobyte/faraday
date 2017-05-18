import requests
import argparse
import csv

def delete_cwe_db(couchdb_url):
    response = requests.delete(couchdb_url + "/cwe")
    if response.status_code == 200:
        print "[*] Deleted old CWE database: OK"
    else:
        print "[*] Deleted old CWE database: FAIL"
        print response.text


def delete_summary_csv(file):

    with open(file, "r") as source:
        reader = csv.reader(source)


def main():

    parser = argparse.ArgumentParser(prog='migrateCWEdatabase', epilog="Example: ./%(prog)s.py")

    parser.add_argument('-c', '--couchdburi', action='store', type=str,
                        dest='couchdb', default="http://127.0.0.1:5984",
                        help='Couchdb URL (default http://127.0.0.1:5984)')

    parser.add_argument('-f', '--filecsv', action='store', type=str,
                        dest='filecsv',
                        help='CSV vulnerability template file')

    args = parser.parse_args()

    delete_cwe_db(args.couchdb)
    delete_summary_csv(args.filecsv)

if __name__ == "__main__":
    main()
