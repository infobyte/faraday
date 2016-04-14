#!/usr/bin/env python2.7
'''
Faraday Penetration Test IDE
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

host = os.environ["FARADAY_ZSH_HOST"]
port = int(os.environ["FARADAY_ZSH_RPORT"])

url_input = "http://%s:%d/cmd/input" % (host, port)
url_output = "http://%s:%d/cmd/output" % (host, port)
url_active_plugins = "http://%s:%d/cmd/active-plugins" % (host, port)
headers = {'Content-type': 'application/json', 'Accept': 'application/json'}



def send_cmd(pid, cmd):

    data = {'pid': pid, 'cmd': cmd}
    new_cmd = cmd
    response = ''

    try:
        request = requests.post(
            url_input,
            data=json.dumps(data),
            headers=headers)

        if request.status_code == 200:

            response = request.json()
            if response.get("cmd") is not None:
                new_cmd = response.get("cmd")

            output_file = "%s/%s%s.output" % (
                output_folder, data['pid'], uuid.uuid4())

            new_cmd += " >&1 > %s" % output_file
    except:
        response = ''
    finally:
        print response
        return 0

def gen_output(pid):
    print "%s/%s.%s.output" % (output_folder, pid, uuid.uuid4())
    return 0

def send_output(cmd, pid, exit_code, output_file):
    output_file = open(output_file)
    output = output_file.read()

    data = {
        'pid': pid,
        'exit_code': exit_code,
        'output': base64.b64encode(output)
    }

    response = requests.post(url_output,
                             data=json.dumps(data),
                             headers=headers)
    if response.status_code != 200:
        print response.json()
        return -1
    return 0


def main(argv):
    if len(argv) < 3:
        sys.exit(0)

    action = argv[1]

    dispatcher = {
        'send_cmd': send_cmd,
        'send_output': send_output,
        'gen_output': gen_output}

    if action in dispatcher.keys():
        if len(argv[2:]) > 0:
            dispatcher[action](*argv[2:])

    #sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
