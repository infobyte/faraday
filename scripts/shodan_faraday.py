#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import shodan
import sys
import xmlrpclib
import argparse
import base64

__author__     = "Francisco Amato"
__copyright__  = "Copyright 2014, Faraday Project"
__credits__    = ["Francisco Amato"]
__license__    = ""
__version__    = "1.0.1"
__maintainer__ = "Francisco Amato"
__email__      = "famato@infobytesec.com"
__status__     = "Development"

# Configuration
SHODAN_API_KEY = "INSERT SHODAN KEY HERE"

def send_faraday(result):
    print 'IP: %s' % result['ip_str']    

    if result['data'] is not None:
        result['data'] = base64.b64encode(str(result['data'])) #fix: to avoid non ascii caracters

    if args.debug == "1":
    	print '==============='
        for key in result.keys():
           print "kname:" + key + ", value:" + str(result[key])

    h_id = api.createAndAddHost(str(result['ip_str']),str(result['os']) if result['os'] is not None else "")
    i_id = api.createAndAddInterface(h_id,str(result['ip_str']),"00:00:00:00:00:00", str(result['ip_str']), "0.0.0.0", "0.0.0.0",[],
          "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
          [],"",result['hostnames'] if result['hostnames'] is not None else [])
    s_id = api.createAndAddServiceToInterface(h_id, i_id, str(result['product']) if result.has_key('product') else str(result['port']),
        "tcp",str(result['port']),"open",str(result['version']) if result.has_key('version') else "")
    if result['data'] is not None:
    	n_id = api.createAndAddNoteToService(h_id,s_id,"shadon_response",str(result['data']))
    
    #Notes - Information geo/shadon
    n_id = api.createAndAddNoteToHost(h_id,"geo_country",result['location']['country_name'] if result['location']['country_name']  is not None else "" )
    n_id = api.createAndAddNoteToHost(h_id,"geo_latitude",result['location']['latitude'] if result['location']['latitude']  is not None else "")
    n_id = api.createAndAddNoteToHost(h_id,"geo_longitude",result['location']['longitude']  if result['location']['longitude']  is not None else "")
    n_id = api.createAndAddNoteToHost(h_id,"shadon_q",args.shodan_query)

# Input validation

#arguments parser
parser = argparse.ArgumentParser(prog='shodan_faraday', epilog="Example: ./%(prog)s.py -q Apache")
parser.add_argument('-q', '--query', action="store", type=str, required=True, dest='shodan_query', help='shadon search query')
parser.add_argument('-c', '--count', action="store", type=str, required=False, dest='count', default="50", help='Numbers of results to get, for all results use "all"')
parser.add_argument('-a', '--shodan_key', action="store", type=str, dest='skey', default=SHODAN_API_KEY, help='shodan key api')
parser.add_argument('--faradayapi', '-fapi', action='store', type=str, dest='faradayapi', default="http://127.0.0.1:9876/", help='Faraday URL Api')
parser.add_argument('--debug', '-d', action='store', type=str, dest='debug', default="0", help='Debug <0>,<1>')
parser.add_argument('--version', "-v", action='version', version='%(prog)s v1.1')

#arguments put in variables
args = parser.parse_args()

try:
    # Setup the apis
    api = xmlrpclib.ServerProxy(args.faradayapi)
    shodan_api = shodan.Shodan(args.skey)
    c_page=1

    results = shodan_api.search(args.shodan_query)
    print 'Results found: %s, query "%s"' % (results['total'], args.shodan_query)
    
    for r in shodan_api.search_cursor(args.shodan_query, minify=True, retries=5):
        if args.count != "all" and c_page >= int(args.count):
     		break

        send_faraday(r)
        c_page+=1


except xmlrpclib.ProtocolError as e:
    if e.errcode == 500:
    	print "[ERROR] Faraday Api error:", sys.exc_info()[0]
        pass
    else:
        print "[ERROR] Unexpected error:", sys.exc_info()[0]
        print e.__dict__
        raise
except shodan.client.APIError as e:
    print "[ERROR] :", sys.exc_info()[0]
    raise

except Exception as e:
    print "Unexpected error:", sys.exc_info()[0]
    print e.__dict__
    raise


