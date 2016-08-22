"""This module is intended as a brige between the client objects and
the server. It implements classes with the same
interface as those in the client, intended to mimic the behavior
of the Faraday Objects. These classes are private to the module, as the
user should never create one: they are used as a wrapper to share
an interface between the Faraday objects and the information you get
from the server via the requests.

This way, you can write a function that deals with hosts abstractly,
without worring if you are gonna call it with a host from memory or request
the server for that host.

>> def get_host_vulns(host):
>>     return host.getVulns()

>> host_from_memory = ModelController.getHost('127.0.0.1')
>> host_from_server = ServerAPI.get_hosts('workspace', name='127.0.0.1')
>> vulns_from_memory = get_host_vulns(host_from_memory)
>> vuln_from_server = get_host_vulns(host_from_server)
>> print(vulns_from_memory == vulns_from_server)
True

The only public utilities exposed by the module are
* get_hosts
* get_all_vulns
* get_vulns
* get_vulns_web
* get_interfaces
* get_services
* get_host_amount
* get_all_vuln_amount
* get_vulns_amounts
* get_vuln_web_amount
* get_interface_amount
* get_service_aount

They all take a workspace's name as a string and an arbitrary numbers of
params, to filter your search. For example, if you want only the first
50 hosts ordered descendently by amount of vulns:

ServerAPI.get_hosts('workspace_name', page_size='50', sort='vulns', dir='desc')

Their docstring have more specific information.
"""

import requests, json
from config.configuration import getInstanceConfiguration

class CantCommunicateWithServerError(Exception):
    def __str__(self):
        return "Couldn't get a valid response from the server."

CONF = getInstanceConfiguration()
def _get_server_api_uri():
    server_uri = CONF.getCouchURI()
    if not server_uri:
        raise CantCommunicateWithServerError()
    server_api_uri = "{0}/_api".format(server_uri)
    return server_api_uri

def _create_request_uri(workspace_name, get_this):
    """Creates a request URI for the server. Takes the workspace name
    as a string, a get_this paramter which is the object you want to
    query as a string ('host', 'interface', etc) .

    Return the request_uri as a string.
    """
    server_api_uri = _get_server_api_uri()
    request_uri = '{0}/ws/{1}/{2}'.format(server_api_uri, workspace_name, get_this)
    return request_uri

def _get(request_uri, **params):
    """Get from the request_uri. Takes an arbitrary number of paramethers
    to customize the request_uri if necessary.

    Will raise a CantCommunicateWithServerError if requests can stablish
    connection to server or if response is not equal to 200.

    Return a dictionary with the information in the json.
    """
    payload = {}
    for param in params:
        payload[param] = params[param]
    try:
        print request_uri, payload
        answer = requests.get(request_uri, params=payload)
        if answer.status_code != 200:
            raise requests.exceptions.ConnectionError()
    except requests.exceptions.ConnectionError:
        raise CantCommunicateWithServerError()
    try:
        dictionary = answer.json()
    except ValueError:
        dictionary = {}
    return dictionary

def _get_raw_hosts(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the hosts table."""
    request_uri = _create_request_uri(workspace_name, 'hosts')
    return _get(request_uri, **params)

def _get_raw_vulns(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the vulns table."""
    request_uri = _create_request_uri(workspace_name, 'vulns')
    return _get(request_uri, **params)

def _get_raw_interfaces(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the interfaces table."""
    request_uri = _create_request_uri(workspace_name, 'interfaces')
    return _get(request_uri, **params)

def _get_raw_services(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the services table."""
    request_uri = _create_request_uri(workspace_name, 'services')
    return _get(request_uri, **params)

def _get_faraday_ready_objects(workspace_name, faraday_object, row_name, **params):
    """Takes a workspace name, a faraday object ('hosts', 'vulns',
    'interfaces' or 'services') a row_name (the name of the row where
    the information about the objects live) and an arbitray number
    of params to customize to request.

    Return a list of faraday objects
    (_Host, _Interface, _Service, _Vuln, _WevVuln) which the same interface
    for getting attribuetes than those defined my the ModelController.
    """
    if not isinstance(workspace_name, basestring):
        workspace_name = workspace_name.name
    object_to_func_and_class =  {'hosts': (_get_raw_hosts, _Host),
                                 'vulns': (_get_raw_vulns, _Vuln),
                                 'interfaces': (_get_raw_interfaces, _Interface),
                                 'services': (_get_raw_services, _Service)}

    appropiate_function, appropiate_class = object_to_func_and_class[faraday_object]
    appropiate_dictionary = appropiate_function(workspace_name, **params)
    faraday_objects = []
    if appropiate_dictionary:
        for raw_object in appropiate_dictionary[row_name]:
            faraday_objects.append(appropiate_class(raw_object, workspace_name))
    return faraday_objects

def get_hosts(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Host objects.
    """
    return _get_faraday_ready_objects(workspace_name, 'hosts', 'rows', **params)

def get_all_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Vuln and VulnWeb objects.
    """
    return _get_faraday_ready_objects(workspace_name, 'vulns', 'vulnerabilities', **params)

def get_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Vuln.

    If you want to get Vulns and WebVulns, use get_all_vulns function.
    """
    return get_all_vulns(workspace_name, type='Vulnerability', **params)

def get_vulns_web(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of VulnWeb objects.
    """
    return get_all_vulns(workspace_name, type='VulnerabilityWeb', **params)

def get_interfaces(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Interfaces objects
    """
    return _get_faraday_ready_objects(workspace_name, 'interfaces', 'interfaces', **params)

def get_services(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Services objects
    """
    return _get_faraday_ready_objects(workspace_name, 'services', 'services', **params)

def get_hosts_amount(workspace_name):
    return int(_get_raw_hosts(workspace_name)['total_rows'])

def get_services_amount(workspace_name):
    return len(get_services(workspace_name))

def get_interfaces_amount(workspace_name):
    return len(get_interfaces(wokspace_name))

def get_services_amount(workspace_name):
    return len(get_services(workspace_name))

def get_all_vulns_amount(workspace_name):
    return int(_get_raw_vulns(workspace_name)['count'])

class _Host:
    """A simple Host class. Should implement all the methods of the
    Host object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
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
        service = get_interfaces(self._workspace_name, couchid=interface_couch_id)
        return service[0]
    def getAllInterfaces(self):
        return get_interfaces(self._workspace_name, host=self.server_id)
    def getServices(self):
        services = []
        interfaces = self.getAllInterfaces()
        for interface in interfaces:
            services.append(services.getAllServices())
        return interfaces

class _Interface:
    """A simple Interface class. Should implement all the methods of the
    Interface object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
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

    def __str__(self): return "{0}".format(self.name)
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
        service = get_services(self._workspace_name, couchid=service_couch_id)
        return service[0]
    def getAllServices(self):
        return get_services(self._workspace_name, interface=self._server_id)
    def getVulns(self):
        vulns = []
        services = self.getAllServices()
        for service in services:
            vulns_in_service = service.getVulns()
            for vuln in vulns_in_service:
                vulns.append(vuln)
        return vulns

class _Service:
    """A simple Service class. Should implement all the methods of the
    Service object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
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
        self.vuln_amount = int(service['vulns'])

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getID(self): return self.id
    def getName(self): return self.name
    def getDescription(self): return self.description
    def getStatus(self): return self.status
    def getPorts(self): return [self.ports]  # this is a list of one element in faraday
    def getVersion(self): return self.version
    def getProtocol(self): return self.protocol
    def isOwned(self): return self.owned
    def getVulns(self): return get_all_vulns(self._workspace_name, service=self.name)

class _Vuln:
    """A simple Vuln class. Should implement all the methods of the
    Vuln object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
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
    """A simple VulnWeb class. Should implement all the methods of the
    VulnWeb object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    def __init__(self, vuln_web, workspace_name):
        self._workspace_name = workspace_name
        self.class_signature = 'VulnerabilityWeb'
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
