#!/usr/bin/python
'''
    Copyright (C) 2016 xtr4nge [_AT_] gmail.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os, sys, getopt
import urllib2
import json
import requests
from requests import session

requests.packages.urllib3.disable_warnings() # DISABLE SSL CHECK WARNINGS

gVersion = "1.0"
server = "http://127.0.0.1:8000";
token = "e5dab9a69988dd65e578041416773149ea57a054"

def usage():
    print "\nFruityWiFi API " + gVersion + " by @xtr4nge"
    
    print "Usage: ./client <options>\n"
    print "Options:"
    print "-x <command>, --execute=<commnd>      exec the command passed as parameter."
    print "-t <token>,   --token=<token>         authentication token."
    print "-s <server>,  --server=<server>       FruityWiFi server [http{s}://ip:port]."
    print "-h                                    Print this help message."
    print ""
    print "FruityWiFi: http://www.fruitywifi.com"
    print ""

def parseOptions(argv):
    
    v_execute = "/log/dhcp"
    v_token = token
    v_server = server
    
    try:                                
        opts, args = getopt.getopt(argv, "hx:t:s:", 
                                   ["help","execute=","token=","server="])
        
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-x", "--execute"):
                v_execute = arg
            elif opt in ("-t", "--token"):
                v_token = arg
            elif opt in ("-s", "--server"):
                v_server = arg
                
        return (v_execute, v_token, v_server)
                    
    except getopt.GetoptError:
        usage()
        sys.exit(2)

(execute, token, server) = parseOptions(sys.argv[1:])

class webclient:

    def __init__(self, server, token):

        self.global_webserver = server
        self.path = "/modules/api/includes/ws_action.php"
        self.s = requests.session()
        self.token = token

    def login(self):

        payload = {
            'action': 'login',
            'token': self.token
        }

        self.s = requests.session()
        self.s.get(self.global_webserver, verify=False) # DISABLE SSL CHECK
        self.s.post(self.global_webserver + '/login.php', data=payload)

    def loginCheck(self):

        response = self.s.get(self.global_webserver + '/login_check.php')

        if response.text != "":
            self.login()

        if response.text != "":
            print json.dumps("[FruityWiFi]: Ah, Ah, Ah! You didn't say the magic word! (check API token and server)")
            sys.exit()

        return True

    def submitPost(self, data):
        response = self.s.post(self.global_webserver + data)
        return response.json

        if response.text == "":
            return True
        else:
            return False

    def submitGet(self, data):
        response = self.s.get(self.global_webserver + self.path + "?" + data)
        #print response.headers
        #print "debug: " + response.text
        #print response.json

        return response

try:
    w = webclient(server, token)
    w.login()
    w.loginCheck()
except Exception, e:
    print json.dumps("[FruityWiFi]: There is something wrong (%s)" % e)
    sys.exit(1)
        
_exec = "/log/dhcp"
_exec = execute
if _exec != "":
    try:
        out =  w.submitGet("api=" + str(_exec))
        json_output = out.json()
    except Exception, e:
        print json.dumps("[FruityWiFi]: There is something wrong (%s)" % e)
        sys.exit(1)
        
output = []
if _exec == "/log/dhcp":
    for item in json_output:
        if item.strip() != "":
            output = [item.split(" ")]
else:
    output = json_output

if len(output) > 0:
    print json.dumps(output)
else:
    print json.dumps("No clients connected")
