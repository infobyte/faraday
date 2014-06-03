#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import json
import requests
import sys
import uuid
import os
import base64

#TODO: load output dir from faraday config
#check if output dir already exists, otherwise create it
file_path = os.path.realpath(__file__)
output_folder = "%s/output" % os.path.dirname(file_path)
if not os.path.exists(output_folder):
    os.mkdir(output_folder)

#TODO: Load this from faraday config
host = "127.0.0.1"
port = 9977

url_input = "http://%s:%d/cmd/input" % (host, port)
url_output = "http://%s:%d/cmd/output" % (host, port)
url_active_plugins = "http://%s:%d/cmd/active-plugins" % (host, port)
headers = {'Content-type': 'application/json', 'Accept': 'application/json'}


def send_cmd(cmd):
    data = {"cmd": cmd}
    new_cmd = cmd
    result = False
    try:
        response = requests.post(url_input,
                                 data=json.dumps(data),
                                 headers=headers)

        if response.status_code == 200:
            json_response = response.json()
            if "cmd" in json_response.keys():
                if json_response.get("cmd") is not None:
                    new_cmd = json_response.get("cmd")
            if "custom_output_file" in json_response.keys():
                output_file = json_response.get("custom_output_file")
                if output_file is None:
                    output_file = "%s/%s.output" % (output_folder, uuid.uuid4())
                    new_cmd += " >&1 > %s" % output_file

                new_cmd += " && python2 %s send_output %s \"%s\"" % (file_path, base64.b64encode(cmd), output_file)
        result = True
    except:
        new_cmd = cmd
    finally:
        print new_cmd
        return result


def send_output(cmd, output_file):
    output_file = open(output_file)
    output = output_file.read()
    data = {"cmd": base64.b64decode(cmd), "output": base64.b64encode(output)}
    response = requests.post(url_output,
                             data=json.dumps(data),
                             headers=headers)
    if response.status_code != 200:
        print "something wrong"
        print response.json()
        return True
    return False


def main(argv):
    if len(argv) < 3:
        sys.exit(0)

    action = argv[1]

    dispatcher = {'send_cmd': send_cmd, 'send_output': send_output}

    if action in dispatcher.keys():
        if len(argv[2:]) > 0:
            dispatcher[action](*argv[2:])

    #sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
