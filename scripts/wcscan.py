#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import subprocess                                   
import argparse                                                                                         
from lxml import etree as ET    
import os.path
from os.path import basename
import __builtin__
import re

from wcscans import phpini, webconfig

def is_valid_address(parser,arg):
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",arg):
        return arg
    else:
        parser.error('{} is not a valid address!'.format(arg))

def are_valid_files(parser,*args):
    for arg in args:
        return is_valid_file(parser, arg)
        
def is_valid_file(parser, arg):
    if not os.path.isfile(arg):
        parser.error('{} does not exist!'.format(arg))
    else:
            try:
                if re.search("XML",subprocess.check_output("file {}".format(arg), 
                             shell=True, 
                             stdin=subprocess.PIPE, 
                             stderr=subprocess.PIPE)):
                    if not os.path.isfile("wcscans/DotNetConfig.xsd"):
                        parser.error("DotNetConfig.xsd is missing, cannot validate the web.config".format(arg))
                    else:
                        f = open("wcscans/DotNetConfig.xsd","r")
                        webconfig_schema = ET.XMLSchema(ET.parse(f))
                        webconfig_schema.validate(ET.parse(arg))    
        
                if re.search("\.ini$",arg):
                    pass
                    
                return arg  
            except ET.ParseError:   
                parser.error("{} is not a valid file!".format(arg))

parser = argparse.ArgumentParser(prog='Wcscan')
parser.add_argument('files', nargs='+',
                    type=lambda *args: are_valid_files(parser,*args),
                    help='''configuration files as inputs, 
                            separated by a space.
                            currently supported: 
                            php.ini and web.config''')
parser.add_argument('-r', action='store_true', dest='recmode',
                    help='enable the recommendation mode')      
parser.add_argument('-host', action='store', 
                                        type=lambda arg: is_valid_address(parser,arg), 
                                        dest='host', default="127.0.0.1",
                                        help='to give the IP address of the conf file owner')
parser.add_argument('-port', action='store', type=int, 
                                        dest='port', default="80",
                                        help='to give a associated port')                                               
parser.add_argument('--xml', action='store', type=str, dest='xmloutput', 
                    help='enabled the XML output in a specified file')                              
parser.add_argument('--version', "-v", action='version', 
                    version='%(prog)s v1.0 by Morgan Lemarechal')
args = parser.parse_args()  

print basename("/a/b/c.txt")
print """\033[0;33m                  
     __        __                      
     \ \  /\  / /__ ___  ___ __ _ _ __  
      \ \/  \/ / __/ __|/ __/ _` | '_ \ 
       \  /\  / (__\__ \ (_| (_| | | | |
        \/  \/ \___|___/\___\__,_|_| |_|
         Version v1.0: November 2014    
              Morgan Lemarechal\033[0m"""
    
if args.xmloutput:
    root = ET.Element("wcscan")
else:
    scan = None
    
for file in args.files:
    try:
        print "\n[+]Perfoming the scan of \033[1;30m{}\033[0m...".format(file)
        
        #------------------------------XML_Export------------------------------#    
        if args.xmloutput:
            scan = ET.SubElement(root, "scan")
            scan.set('file',basename(file))
            scan.set('host',args.host)
            scan.set('port',str(args.port))
        #------------------------------XML_Export------------------------------#    
        
        if re.search("XML",subprocess.check_output("file {}".format(file), 
                    shell=True, 
                    stdin=subprocess.PIPE, 
                    stderr=subprocess.PIPE)):       
            #------------------------------XML_Export------------------------------#    
            if args.xmloutput:
                scan.set('type','webconfig')
            #------------------------------XML_Export------------------------------#    
            webconfig.scanner(file,args.recmode,scan)
            
        if re.search("\.ini$",file):
            #------------------------------XML_Export------------------------------#    
            if args.xmloutput:
                scan.set('type','phpini')
            #------------------------------XML_Export------------------------------#    
            phpini.scanner(file,args.recmode,scan)
            
        #------------------------------XML_Export------------------------------#                
        if args.xmloutput:
            tree = ET.ElementTree(root)
            try:
                fo = open(args.xmloutput, "w")
                tree.write(fo) 
                fo.close()
            except IOError:
                sys.exit('\033[0;41m[+]XML export failed.\033[0m')
        #------------------------------XML_Export------------------------------#        
        
    except KeyboardInterrupt:       
        print "\n[+]Interrupting the checking of \033[1;30m{}\033[0m...".format(file)
