from __future__ import absolute_import

import requests
import json


class ApiError(Exception):
    def __init__(self, message):
        super(ApiError, self).__init__(message)


class Structure:
    def __init__(self, **entries):
        self.__dict__.update(entries)

    @property
    def id(self):
        if hasattr(self, '_id'):
            return self._id
        return None

    @property
    def class_signature(self):
        if hasattr(self, 'type'):
            return self.type
        return None

    @property
    def parent_id(self):
        if hasattr(self, 'parent'):
            return self.parent
        return None

    def getMetadata(self):
        if hasattr(self, 'metadata'):
            return self.metadata
        return None


class Api:
    def __init__(self, workspace, username, password, base='http://127.0.0.1:5985/_api/'):
        self.base = base
        self.workspace = workspace
        self.cookies = self.login(username, password)
        if self.cookies is None:
            raise UserWarning('Invalid username or password')

    def _url(self, path):
        return self.base + 'v2/' + path

    def _get(self, url, object_name):
        response = requests.get(url, cookies=self.cookies)
        if response.status_code == 401:
            raise ApiError('Unauthorized operation trying to get {}'.format(object_name))
        if response.status_code != 200:
            raise ApiError('Cannot fetch {}'.format(object_name))
        return json.loads(response.content)

    def _post(self, url, data, object_name):
        response = requests.post(url, json=data, cookies=self.cookies)
        if response.status_code == 401:
            raise ApiError('Unauthorized operation trying to create {}'.format(object_name))
        if response.status_code != 201:
            raise ApiError('Unable to create {}'.format(object_name))
        return json.loads(response.content)

    def _put(self, url, data, object_name):
        response = requests.put(url, json=data, cookies=self.cookies)
        if response.status_code == 401:
            raise ApiError('Unauthorized operation trying to update {}'.format(object_name))
        if response.status_code != 200:
            raise ApiError('Unable to update {}'.format(object_name))
        return json.loads(response.content)

    def _delete(self, url, object_name):
        response = requests.delete(url, cookies=self.cookies)
        if response.status_code == 401:
            raise ApiError('Unauthorized operation trying to delete {}'.format(object_name))
        if response.status_code != 204:
            raise ApiError('Unable to delete {}'.format(object_name))
        return response.ok

    def login(self,  username, password):
        auth = {"email": username, "password": password}
        try:
            resp = requests.post(self.base + 'login', json=auth)
            if resp.status_code == 401:
                return None
            else:
                return resp.cookies
        except requests.adapters.ConnectionError:
            return None
        except requests.adapters.ReadTimeout:
            return None

    def get_vulnerabilities(self):
        return [Structure(**item['value']) for item in self._get(self._url('ws/{}/vulns'.format(self.workspace)),
                                                                 'vulnerabilities')['vulnerabilities']]

    def update_vulnerability(self, vulnerability):
        return Structure(**self._put(self._url('ws/{}/vulns/{}/'.format(self.workspace, vulnerability.id)),
                                     vulnerability.__dict__, 'vulnerability'))

    def delete_vulnerability(self, vulnerability_id):
        return self._delete(self._url('ws/{}/vulns/{}/'.format(self.workspace, vulnerability_id)), 'vulnerability')

    def get_services(self):
        return [Structure(**item['value']) for item in self._get(self._url('ws/{}/services'.format(self.workspace)),
                                                                 'services')['services']]

    def get_filtered_services(self, **params):
        services = self.get_services()
        filtered_services = []
        for key, value in params.items():
            for service in services:
                if hasattr(service, key) and \
                        (getattr(service, key, None) == value or str(getattr(service, key, None)) == value):
                    filtered_services.append(service)
        return filtered_services

    def update_service(self, service):
        if isinstance(service.ports, int):
            service.ports = [service.ports]
        else:
            service.ports = []
        return Structure(**self._put(self._url('ws/{}/services/{}/'.format(self.workspace, service.id)),
                                     service.__dict__, 'service'))

    def delete_service(self, service_id):
        return self._delete(self._url('ws/{}/services/{}/'.format(self.workspace, service_id)), 'service')

    def get_hosts(self):
        return [Structure(**item['value']) for item in self._get(self._url('ws/{}/hosts'.format(self.workspace)),
                                                                 'hosts')['rows']]

    def get_filtered_hosts(self, **params):
        hosts = self.get_hosts()
        filtered_hosts = []
        for key, value in params.items():
            for host in hosts:
                if hasattr(host, key) and \
                        (getattr(host, key, None) == value or str(getattr(host, key, None)) == value):
                    filtered_hosts.append(host)
        return filtered_hosts

    def update_host(self, host):
        return Structure(**self._put(self._url('ws/{}/hosts/{}/'.format(self.workspace, host.id)),
                                     host.__dict__, 'hosts'))

    def delete_host(self, host_id):
        return self._delete(self._url('ws/{}/hosts/{}/'.format(self.workspace, host_id)), 'host')

    def get_vulnerability_templates(self):
        return [Structure(**item['doc']) for item in self._get(self._url('vulnerability_template'), 'templates')['rows']]

    def get_filtered_templates(self, **params):
        templates = self.get_vulnerability_templates()
        filtered_templates = []
        for key, value in params.items():
            for template in templates:
                if hasattr(template, key) and \
                        (getattr(template, key, None) == value or str(getattr(template, key, None)) == value):
                    filtered_templates.append(template)
        return filtered_templates
# I'm Py3