#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import requests
import json
import base64


class RestApiClient(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.url = "http://%s:%d/" % (self.hostname, self.port)
        self.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}


class ModelRestApiClient(RestApiClient):
    def __init__(self, hostname, port):
        super(ModelRestApiClient, self).__init__(hostname, port)

    def _create(self, obj_class_url, **kwargs):
        url = self.url + ('model/%s' % obj_class_url)
        data = {}
        for k, v in kwargs.items():
            data[k] = v
        obj_id = None
        try:
            response = requests.put(
                url, data=json.dumps(data),
                headers=self.headers)
            if response.status_code == 200:
                json_response = response.json()
                obj_id = json_response.get('id')
        except:
            pass
        return obj_id

    def createHost(self, name, os):
        return self._create("host", name=name, os=os)

    def createInterface(self, name, mac, ipv4_address, ipv4_mask,
                        ipv4_gateway, ipv4_dns, ipv6_address, ipv6_prefix,
                        ipv6_gateway, ipv6_dns, network_segment,
                        hostname_resolution, parent_id):
        return self._create(
            "interface", name=name, mac=mac, ipv4_address=ipv4_address,
            ipv4_mask=ipv4_mask, ipv4_gateway=ipv4_gateway, ipv4_dns=ipv4_dns,
            ipv6_address=ipv6_address, ipv6_prefix=ipv6_prefix,
            ipv6_gateway=ipv6_gateway, ipv6_dns=ipv6_dns,
            network_segment=network_segment,
            hostname_resolution=hostname_resolution,
            parent_id=parent_id)

    def createService(self, name, protocol, ports, status, version,
                      description, parent_id):
        return self._create(
            "service", name=name, protocol=protocol, ports=ports,
            status=status, version=version, description=description,
            parent_id=parent_id)

    def createVuln(self, name, desc, ref, severity, resolution, parent_id):
        return self._create(
            "vuln", name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, parent_id=parent_id)

    def createVulnWeb(self, name, desc, ref, severity, resolution, website, path,
                      request, response, method, pname, params, query, category,
                      parent_id):
        return self._create(
            "vulnweb", name=name, desc=desc, ref=ref, severity=severity,
            resolution=resolution, website=website, path=path, request=request,
            response=response, method=method, pname=pname, params=params, query=query,
            category=category, parent_id=parent_id)

    def createNote(self, name, text, parent_id):
        return self._create("note", name=name, text=text, parent_id=parent_id)

    def createCred(self, username, password, parent_id):
        return self._create(
            "cred", username=username, password=password, parent_id=parent_id)


class PluginControllerAPIClient(object):
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.url_input = "http://%s:%d/cmd/input" % (self.hostname, self.port)
        self.url_output = "http://%s:%d/cmd/output" % (self.hostname, self.port)
        self.url_active_plugins = "http://%s:%d/cmd/active-plugins" % (self.hostname, self.port)
        self.headers = {'Content-type': 'application/json', 'Accept': 'application/json'}

    def send_cmd(self, cmd):
        data = {"cmd": cmd}
        new_cmd = cmd
        output_file = None
        try:
            response = requests.post(self.url_input,
                                     data=json.dumps(data),
                                     headers=self.headers)

            if response.status_code == 200:
                json_response = response.json()
                if "cmd" in json_response.keys():
                    if json_response.get("cmd") is not None:
                        new_cmd = json_response.get("cmd")
                if "custom_output_file" in json_response.keys():
                    output_file = json_response.get("custom_output_file")
        except:
            new_cmd = cmd
        finally:
            return new_cmd, output_file

    def send_output(self, cmd, output_file=None):
        # output_file could be None, when there is
        # no output to send
        output = ""
        if output_file:
            output_file = open(output_file)
            output = base64.b64encode(output_file.read())
        data = {"cmd": cmd, "output": output}
        response = requests.post(self.url_output,
                                 data=json.dumps(data),
                                 headers=self.headers)
        if response.status_code != 200:
            return False
        return True
