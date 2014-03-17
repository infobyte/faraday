#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import json
import requests
import sys
import base64
import uuid


class Plugin(object):
    def __init__(self, id, custom_output, output):
        self.id = id
        self.custom_output = custom_output
        self.output = output


def object_decoder(json_obj):
    return Plugin(json_obj['id'], json_obj['custom_output'], json_obj['output'])


def get_cmd(command):
    response = requests.get("http://127.0.0.1:5000/plugins/%s" %
                            (base64.b64encode(command)))
    output = ""

    if response.status_code == 200:
        plugin = json.loads(response.text, object_hook=object_decoder)
        output = "default"
        if plugin.custom_output:
            output = plugin.output

    print output

def send_output(output_file):
    pass


def main():
    if len(sys.argv) != 3:
        sys.exit(1)

    action = sys.argv[1]

    dispatcher = {'get_cmd': get_cmd, 'send_output': send_output}

    dispatcher[action](sys.argv[2])

if __name__ == '__main__':
    main()
