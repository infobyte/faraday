import requests, json
from functools import wraps
from pprint import pprint
#from config.configuration import getInstanceConfiguration
class CantCommunicateWithServerError(Exception):
    def __str__(self):
        return "Couldn't get a valid response from the server."


#CONF = getInstanceConfiguration()
#server_uri = CONF.getCouchURI()
server_uri = 'http://127.0.0.1:5984/_api'
if not server_uri:
    raise ValueError("No server configured!")


class _Host:
    def __init__(self, host, workspace_name):
        self._workspace_name = workspace_name
        self.class_signature = 'Host'
        self.id = host['id']
        self.server_id = host['_id']
        self.name = host['value']['name']
        self.os = host['value']['os']
        self.vuln_amount = int(host['value']['vulns'])
        self.owned = host['value']['owned']

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getOS(self): return self.os
    def getName(self): return self.name
    def getVulnAmount(self): return self.vuln_amount
    def isOwned(self): return self.owned
    def getID(self): return self.id
    def getVulns(self):
        return get_all_vulns(self._workspace_name, target=self.name)
    def getInterface(self, interface_couch_id):
        interfaces = self.getAllInterfaces()
        desired_interface = [i for i in interfaces if i.id == interface_couch_id]
        return desired_interface[0] if desired_interface else None
    def getAllInterfaces(self):
        return get_interfaces(self._workspace_name, self.server_id)
    def getServices(self):
        services = []
        interfaces = self.getAllInterfaces()
        for interface in interfaces:
            services.append(services.getAllServices())
        return interfaces

class _Interface:
    def __init__(self, interface, workspace_name):
        self._workspace_name = workspace_name
        self.class_signature = 'Interface'
        self.id = interface['id']
        self._server_id = interface['_id']
        self.name = interface['value']['name']
        self.description = interface['value']['description']
        self.hostnames = interface['value']['hostnames']
        self.ipv4 = interface['value']['ipv4']
        self.ipv6 = interface['value']['ipv6']
        self.mac = interface['value']['mac']
        self.network_segment = interface['value']['network_segment']
        self.owned = interface['value']['owned']
        self.ports = interface['value']['ports']

    def getID(self): return self.id
    def getName(self): return self.name
    def getDescription(self): return self.description
    def getHostnames(self): return self.hostnames
    def getIPv4(self): return self.ipv4
    def getIPv6(self): return self.ipv6
    def getMAC(self): return self.mac
    def getNetworkSegment(self): return self.network_segment
    def isOwned(self): return self.owned
    def getService(self, service_couch_id):
        services = self.getAllServices()
    def getAllServices(self):
        return get_services(self._workspace_name, self._server_id)
    def getVulns(self):
        vulns = []
        #services = self.getAllServices()
        #for service in services:
        #    vulns.append(service.getVulns())
        return vulns

class _Service:
    def __init__(self, service, workspace_name):
        self._workspace_name = workspace_name
        self.class_signature = 'Service'
        self.id = service['id']
        self._server_id = service['_id']
        self.name = service['value']['name']
        self.owned = service['value']['owned']
        self.protocol = service['value']['protocol']
        self.ports =  service['value']['ports']
        self.description = service['value']['description']
        self.version = service['value']['version']
        self.status = service['value']['status']

    def getID(self): return self.id
    def getName(self): return self.name
    def getDescription(self): return self.description
    def getStatus(self): return self.status
    def getPorts(self): return [self.ports]  # this is a list of one element in faraday
    def getVersion(self): return self.version
    def getProtocol(self): return self.protocol
    def isOwned(self): return self.owned
    def getVulns(self):
        return get_vulns(self._workspace_name, parent=self.id)

class _Vuln:
    def __init__(self, vuln, workspace_name):
        self._workspace_name = workspace_name
        self.class_signature = 'Vulnerability'
        self.name = vuln['value']['name']
        self.description = vuln['value']['desc']
        self.desc = vuln['value']['desc']
        self.data = vuln['value']['data']
        self.severity = vuln['value']['severity']
        self.refs = vuln['value']['refs']

    def getName(self): return self.name
    def getDescription(self): return self.description
    def getDesc(self): return self.desc
    def getData(self): return self.data
    def getSeverity(self): return self.severity
    def getRefs(self): return self.refs

class _VulnWeb:
    def __init__(self, vuln_web, workspace_name):
        self._workspace_name = workspace_name
        self.name = vuln_web['value']['name']
        self.description = vuln_web['value']['desc']
        self.desc = vuln_web['value']['desc']
        self.data = vuln_web['value']['data']
        self.severity = vuln_web['value']['severity']
        self.refs = vuln_web['value']['refs']
        self.path = vuln_web['value']['path']
        self.website = vuln_web['value']['website']
        self.request = vuln_web['value']['request']
        self.response = vuln_web['value']['response']
        self.method = vuln_web['value']['method']
        self.pname = vuln_web['value']['pname']
        self.params = vuln_web['value']['params']
        self.query = vuln_web['value']['query']
        self.category = vuln_web['value']['category']

    def getName(self): return self.name
    def getDescription(self): return self.description
    def getDesc(self): return self.desc
    def getData(self): return self.data
    def getSeverity(self): return self.severity
    def getRefs(self): return self.refs
    def getPath(self): return self.path
    def getWebsite(self): return self.website
    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getMethod(self): return self.method
    def getPname(self): return self.pname
    def getParams(self): return self.params
    def getQuery(self): return self.query
    def getCategory(self): return self.category

def _create_request_uri(workspace_name, get_this, params=""):
    params = '?{0}'.format(params) if params else ""
    request_uri = '{0}/ws/{1}/{2}{3}'.format(server_uri, workspace_name,
                                              get_this, params)
    return request_uri

def _get(request_uri, **params):
    payload = {}
    for param in params:
        payload[param] = params[param]
    try:
        print request_uri, params
        answer = requests.get(request_uri, params=payload)
    except requests.exceptions.ConnectionError:
        raise CantCommunicateWithServerError()
    try:
        dictionary = answer.json()
    except ValueError:
        dictionary = {}
        #raise ValueError("Server response can't be parsed as a json")
    return dictionary

def _get_raw_hosts(workspace_name, **params):
    request_uri = _create_request_uri(workspace_name, 'hosts')
    return _get(request_uri, **params)

def _get_raw_vulns(workspace_name, **params):
    request_uri = _create_request_uri(workspace_name, 'vulns')
    return _get(request_uri, **params)

def _get_raw_interfaces(workspace_name, host_id, **params):
    request_uri = _create_request_uri(workspace_name, 'interfaces', params='host={0}'.format(host_id))
    return _get(request_uri, **params)

def _get_raw_services(workspace_name, service_id, **params):
    request_uri = _create_request_uri(workspace_name, 'services', params='interface_id={0}'.format(service_id))
    return _get(request_uri, **params)

def _get_faraday_ready_objects(workspace_name, faraday_object, row_name_in_table, host_id=None, interface_id=None, **params):
    if not isinstance(workspace_name, basestring):
        workspace_name = workspace_name.name
    object_to_func =  {'hosts': (_get_raw_hosts, _Host),
                       'vulns': (_get_raw_vulns, _Vuln),
                       'interfaces': (_get_raw_interfaces, _Interface),
                       'services': (_get_raw_services, _Service)}
    appropiate_function, appropiate_class = object_to_func[faraday_object]
    if faraday_object == 'hosts' or faraday_object == 'vulns':
        appropiate_dictionary = appropiate_function(workspace_name, **params)
    elif faraday_object == 'interfaces':
        appropiate_dictionary = appropiate_function(workspace_name, host_id, **params)
    elif faraday_object == 'services':
        appropiate_dictionary = appropiate_function(workspace_name, interface_id, **params)
    faraday_objects = []
    if appropiate_dictionary:
        for raw_object in appropiate_dictionary[row_name_in_table]:
            faraday_objects.append(appropiate_class(raw_object, workspace_name))
    return faraday_objects

def get_hosts(workspace_name, **params):
    return _get_faraday_ready_objects(workspace_name, 'hosts', 'rows', **params)

def get_all_vulns(workspace_name, **params):
    return _get_faraday_ready_objects(workspace_name, 'vulns', 'vulnerabilities', **params)

def get_vulns(workspace_name, **params):
    return get_all_vulns(workspace_name, type='Vulnerability', **params)

def get_vulns_web(workspace_name, **params):
    return get_all_vulns(workspace_name, type='VulnerabilityWeb', **params)

def get_interfaces(workspace_name, parent_host_id, **params):
    return _get_faraday_ready_objects(workspace_name, 'interfaces', 'interfaces', host_id=parent_host_id, **params)

def get_services(workspace_name, parent_interface_id, **params):
    return _get_faraday_ready_objects(workspace_name, 'services', 'services', interface_id=parent_interface_id, **params)
