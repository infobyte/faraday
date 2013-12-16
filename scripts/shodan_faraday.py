#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
from shodan import WebAPI
import xmlrpclib
SHODAN_API_KEY = "insert your API key here"
api = WebAPI(SHODAN_API_KEY)
# Wrap the request in a try/ except block to catch errors
try:
# Search Shodan
	print "Search Shodan"
	results = api.search('apache')
	
	#Connect to faraday
	print "Connecting Farday"
	api = xmlrpclib.ServerProxy("http://127.0.0.1:9876/")
	
	# Show the results
	print 'Results found: %s' % results['total']
	for result in results['matches']:
		if "ip" in result:
			print 'IP: %s' % result['ip']
			print result['data']
			print ''
		
			h_id = api.createAndAddHost(result['ip'],result['os'] if result['os'] is not None else "")
			i_id = api.createAndAddInterface(h_id,result['ip'],"00:00:00:00:00:00", result['ip'], "0.0.0.0", "0.0.0.0",[],
				  "0000:0000:0000:0000:0000:0000:0000:0000","00","0000:0000:0000:0000:0000:0000:0000:0000",
				  [],"",result['hostnames'] if result['hostnames'] is not None else [])
			s_id = api.createAndAddServiceToInterface(h_id, i_id, "www",
								 "tcp",str(result['port']),"open","Apache",result['data'])
			
except Exception, e:
	print 'Error: %s' % e
