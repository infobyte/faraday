#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
Copyright (C) 2014  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import argparse
from bs4 import BeautifulSoup

def main():
    parser = argparse.ArgumentParser(prog='cleanXML', epilog="Example: ./%(prog)s.py")

    parser.add_argument('-i', '--input', action='store', type=str,
        dest='infile', help='XML File to read from', 
        required=True)
    parser.add_argument('-o', '--output', action='store', type=str,
        dest='outfile', help='Filename to write output',
        default="clean.xml")

    args = parser.parse_args()

    xml = open(args.infile, 'r')
    soup = BeautifulSoup(xml.read(), 'xml')

    out = open(args.outfile, 'w')
    out.write(soup.encode('utf-8'))
    out.flush()
    out.close()

    xml.close()

if __name__ == "__main__":
    main()
