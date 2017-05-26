#!/usr/bin/env python

import sys
import xmlrpclib
import argparse
import base64

from reposify_api import *

__author__     = "Reposify"
__version__    = "1.0.0"
__email__      = "support@reposify.com"
__status__     = "Development"


def strip_non_ascii(string):
    ''' Returns the string without non ASCII characters'''
    stripped = (c for c in string if 0 < ord(c) < 127)
    return ''.join(stripped)

def send_faraday(results):
    for device in results['devices']:
        send_faraday_device(device)


def send_faraday_device(result):
    print 'IP: %s' % result['ip_address']

    if args.debug == "1":
    	print '==============='
        for key in result.keys():
           print "kname:" + key + ", value:" + str(result[key])

    h_id = api.createAndAddHost(str(result['ip_address']))
    i_id = api.createAndAddInterface(h_id,str(result['ip_address']),"00:00:00:00:00:00", str(result['ip_address']), "0.0.0.0", "0.0.0.0",[],
          "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
          [],"",result['domain'] if result['domain'] is not None else [])

    for service in result['services']:
        s_id = api.createAndAddServiceToInterface(h_id, i_id, str(service['name']) if service.has_key('name') else str(service['port']),
            "tcp",[int(service['port'])],"open",str(service['version']) if service.has_key('version') else "")        
        if service['banner'] is not None:
            service['banner'] = base64.b64encode(strip_non_ascii(str(service['banner']))) #fix: to avoid non ascii caracters

        if service['banner'] is not None:
        	n_id = api.createAndAddNoteToService(h_id,s_id,"banner",str(service['banner']))

    #Notes - Information geo/shadon
    n_id = api.createAndAddNoteToHost(h_id,"geo_country",result['location']['country_name'] if result['location']['country_name']  is not None else "" )
    n_id = api.createAndAddNoteToHost(h_id,"geo_latitude",str(result['location']['latitude']) if result['location']['latitude']  is not None else "")
    n_id = api.createAndAddNoteToHost(h_id,"geo_longitude",str(result['location']['longitude'])  if result['location']['longitude']  is not None else "")
    n_id = api.createAndAddNoteToHost(h_id,"reposify_search_banner",args.reposify_banner)
    n_id = api.createAndAddNoteToHost(h_id,"reposify_search_filters",args.reposify_filters)

# Input validation

#arguments parser
parser = argparse.ArgumentParser(prog='reposify_faraday', epilog="Example: ./%(prog)s.py -q Apache")
parser.add_argument('-b', '--banner', action="store", type=str, required=False, dest='reposify_banner', help='reposify search banner')
parser.add_argument('-f', '--filters', action="store", type=str, required=False, dest='reposify_filters', help='reposify search filter')
parser.add_argument('-c', '--count', action="store", type=str, required=False, dest='count', default="1", help='Numbers of pages of results to get')
parser.add_argument('-a', '--reposify_key', action="store", type=str, required=True, dest='skey', help='reposify key api')
parser.add_argument('--faradayapi', '-fapi', action='store', type=str, dest='faradayapi', default="http://127.0.0.1:9876/", help='Faraday URL Api')
parser.add_argument('--debug', '-d', action='store', type=str, dest='debug', default="0", help='Debug <0>,<1>')
parser.add_argument('--version', "-v", action='version', version='%(prog)s v1.1')

#arguments put in variables
args = parser.parse_args()

try:
    # Setup the apis
    api = xmlrpclib.ServerProxy(args.faradayapi)    

    results = reposify_search(args.skey, args.reposify_banner, args.reposify_filters, 1)
    print 'Results found: %s, banner "%s", filters "%s' % (results['total_count'], args.reposify_banner, args.reposify_filters)
    send_faraday(results)
    
    if results['pagination']['has_more'] == True:        
        for c_page in range(1,int(args.count)):            
            results = reposify_search(args.skey, args.reposify_banner, args.reposify_filters, c_page + 1)
            send_faraday(results)
            if results['pagination']['has_more'] != True:
                break;

except xmlrpclib.ProtocolError as e:
    if e.errcode == 500:
    	print "[ERROR] Faraday Api error:", sys.exc_info()[0]
        pass
    else:
        print "[ERROR] Unexpected error:", sys.exc_info()[0]
        print e.__dict__
        raise

except Exception as e:
    print "Unexpected error:", sys.exc_info()[0]
    print e.__dict__
    raise



