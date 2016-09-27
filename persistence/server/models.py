#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import glob
import os
import sys
from threading import Lock
from persistence.server import server
from persistence.server.utils import (force_unique,
                                      get_host_properties,
                                      get_interface_properties,
                                      get_service_properties,
                                      get_vuln_properties,
                                      get_vuln_web_properties,
                                      get_note_properties,
                                      get_credential_properties,
                                      get_command_properties,
                                      WrongObjectSignature)

from model.diff import ModelObjectDiff, MergeSolver
from model.conflict import ConflictUpdate
from config.configuration import getInstanceConfiguration
from functools import wraps

CONF = getInstanceConfiguration()

_CHANGES_LOCK = Lock()
def get_changes_lock():
    return _CHANGES_LOCK

_LOCAL_CHANGES_ID_TO_REV = {}
def local_changes():
    return _LOCAL_CHANGES_ID_TO_REV

def _ignore_in_changes(func):
    @wraps(func)
    def func_wrapper(*args, **kwargs):
        with get_changes_lock():
            json = func(*args, **kwargs)
            if json.get('ok'):
                _LOCAL_CHANGES_ID_TO_REV[json['id']] = json['rev']
        return json
    return func_wrapper

def _get_faraday_ready_objects(workspace_name, faraday_ready_object_dictionaries,
                               faraday_object_name):
    """Takes a workspace name, a faraday object ('hosts', 'vulns',
    'interfaces' or 'services') a row_name (the name of the row where
    the information about the objects live) and an arbitray number
    of params to customize to request.

    Return a list of faraday objects
    (_Host, _Interface, _Service, _Vuln, _WevVuln) which the same interface
    for getting attribuetes than those defined my the ModelController.
    """
    object_to_class = {'hosts': _Host,
                       'vulns': _Vuln,
                       'vulns_web': _VulnWeb,
                       'interfaces': _Interface,
                       'services': _Service,
                       'notes': _Note,
                       'credentials': _Credential,
                       'commands': _Command}

    appropiate_class = object_to_class[faraday_object_name]
    faraday_objects = []
    if faraday_ready_object_dictionaries:
        for object_dictionary in faraday_ready_object_dictionaries:
            faraday_objects.append(appropiate_class(object_dictionary, workspace_name))
    return faraday_objects

def _get_faraday_ready_hosts(workspace_name, hosts_dictionaries):
    return _get_faraday_ready_objects(workspace_name, hosts_dictionaries, 'hosts')

def _get_faraday_ready_vulns(workspace_name, vulns_dictionaries, vulns_type=None):
    if vulns_type:
        return _get_faraday_ready_objects(workspace_name, vulns_dictionaries, vulns_type)

    vulns = [vuln for vuln in vulns_dictionaries if vuln['value']['type'] == 'Vulnerability']
    web_vulns = [w_vuln for w_vuln in vulns_dictionaries if w_vuln['value']['type'] == 'VulnerabilityWeb']
    faraday_ready_vulns = _get_faraday_ready_objects(workspace_name, vulns, 'vulns')
    faraday_ready_web_vulns = _get_faraday_ready_objects(workspace_name, web_vulns, 'vulns_web')
    return faraday_ready_vulns + faraday_ready_web_vulns

def _get_faraday_ready_services(workspace_name, services_dictionaries):
    return _get_faraday_ready_objects(workspace_name, services_dictionaries, 'services')

def _get_faraday_ready_interfaces(workspace_name, interfaces_dictionaries):
    return _get_faraday_ready_objects(workspace_name, interfaces_dictionaries, 'interfaces')

def _get_faraday_ready_credentials(workspace_name, credentials_dictionaries):
    return _get_faraday_ready_objects(workspace_name, credentials_dictionaries, 'credentials')

def _get_faraday_ready_notes(workspace_name, notes_dictionaries):
    return _get_faraday_ready_objects(workspace_name, notes_dictionaries, 'notes')

def _get_faraday_ready_commands(workspace_name, commands_dictionaries):
    return _get_faraday_ready_objects(workspace_name, commands_dictionaries, 'commands')

def get_changes_stream(workspace_name, **params):
    since = server.get_workspace(workspace_name)['last_seq']
    return server.get_changes_stream(workspace_name, since=since,
                                     heartbeat='1000')

def get_hosts(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Host objects.
    """
    host_dictionaries = server.get_hosts(workspace_name, **params)
    return _get_faraday_ready_hosts(workspace_name, host_dictionaries)

def get_host(workspace_name, host_id):
    """Return the host by host_id. None if it can't be found."""
    return force_unique(get_hosts(workspace_name, couchid=host_id))

def get_all_vulns(workspace_name, **params):
    vulns_dictionaries = server.get_all_vulns(workspace_name, **params)
    return _get_faraday_ready_vulns(workspace_name, vulns_dictionaries)

def get_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Vuln objects.
    """
    vulns_dictionaries = server.get_vulns(workspace_name, **params)
    return _get_faraday_ready_vulns(workspace_name, vulns_dictionaries, vulns_type='vulns')

def get_vuln(workspace_name, vuln_id):
    """Return the Vuln of id vuln_id. None if not found."""
    return force_unique(get_vulns(workspace_name, couchid=vuln_id))

def get_web_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of VulnWeb objects.
    """
    vulns_web_dictionaries = server.get_web_vulns(workspace_name, **params)
    return _get_faraday_ready_vulns(workspace_name, vulns_web_dictionaries, vulns_type='vulns_web')

def get_web_vuln(workspace_name, vuln_id):
    """Return the WebVuln of id vuln_id. None if not found."""
    return force_unique(get_web_vulns(workspace_name, couchid=vuln_id))

def get_interfaces(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Interfaces objects
    """
    interfaces_dictionaries = server.get_interfaces(workspace_name, **params)
    return _get_faraday_ready_interfaces(workspace_name, interfaces_dictionaries)

def get_interface(workspace_name, interface_id):
    """Return the Interface of id interface_id. None if not found."""
    return force_unique(get_interfaces(workspace_name, couchid=interface_id))

def get_services(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Services objects
    """
    services_dictionary = server.get_services(workspace_name, **params)
    return _get_faraday_ready_services(workspace_name, services_dictionary)

def get_service(workspace_name, service_id):
    """Return the Service of id service_id. None if not found."""
    return force_unique(get_services(workspace_name, couchid=service_id))

def get_credentials(workspace_name, **params):
    credentials_dictionary = server.get_credentials(workspace_name, **params)
    return _get_faraday_ready_credentials(workspace_name, credentials_dictionary)

def get_credential(workspace_name, credential_id):
    return force_unique(get_credentials(workspace_name, couchid=credential_id))

def get_notes(workspace_name, **params):
    notes_dictionary = server.get_notes(workspace_name, **params)
    return _get_faraday_ready_notes(workspace_name, notes_dictionary)

def get_note(workspace_name, note_id):
    return force_unique(get_notes(workspace_name, couchid=note_id))

def get_workspace(workspace_name):
    """Return the Workspace of id workspace_name. None if not found."""
    workspace = server.get_workspace(workspace_name)
    return _Workspace(workspace, workspace_name) if workspace else None

def get_commands(workspace_name, **params):
    commands_dictionary = server.get_commands(workspace_name, **params)
    return _get_faraday_ready_commands(workspace_name, commands_dictionary)

def get_command(workspace_name, command_id):
    return force_unique(get_commands(workspace_name, couchid=command_id))

def get_object(workspace_name, object_signature, object_id):
    """Given a workspace name, an object_signature as string  and an arbitrary
    number of query params, return a list a dictionaries containg information
    about 'object_signature' objects matching the query.

    object_signature must be either 'Host', 'Vulnerability', 'VulnerabilityWeb',
    'Interface', 'Service', 'Cred', 'Note' or 'CommandRunInformation'.
    Will raise an WrongObjectSignature error if this condition is not met.
    """
    object_to_func = {_Host.class_signature: get_host,
                      _Vuln.class_signature: get_vuln,
                      _VulnWeb.class_signature: get_web_vuln,
                      _Interface.class_signature: get_interface,
                      _Service.class_signature: get_service,
                      _Credential.class_signature: get_credential,
                      _Note.class_signature: get_note,
                      _Command.class_signature: get_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, object_id)

def get_deleted_object_name_and_type(workspace_name, object_id):
    """Return a tupe of (name, type) for the deleted object of object_id,
    if it can get around CouchDB to do it. Else None"""
    obj_dict = server.get_object_before_last_revision(workspace_name, object_id)
    return (obj_dict['name'], obj_dict['type']) if obj_dict else (None, None)

@_ignore_in_changes
def create_host(workspace_name, host):
    """Take a workspace_name and a host object and save it to the sever.

    Return the server's json response as a dictionary.
    """
    host_properties = get_host_properties(host)
    return server.create_host(workspace_name, **host_properties)

@_ignore_in_changes
def update_host(workspace_name, host):
    host_properties = get_host_properties(host)
    return server.update_host(workspace_name, **host_properties)

@_ignore_in_changes
def create_interface(workspace_name, interface):
    """Take a workspace_name and an interface object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    interface_properties = get_interface_properties(interface)
    return server.create_interface(workspace_name, **interface_properties)

@_ignore_in_changes
def update_interface(workspace_name, interface):
    interface_properties = get_interface_properties(interface)
    return server.update_interface(workspace_name, **interface_properties)

@_ignore_in_changes
def create_service(workspace_name, service):
    """Take a workspace_name and a service object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    service_properties = get_service_properties(service)
    return server.create_service(workspace_name, **service_properties)

@_ignore_in_changes
def update_service(workspace_name, service):
    service_properties = get_service_properties(service)
    return server.update_service(workspace_name, **service_properties)

@_ignore_in_changes
def create_vuln(workspace_name, vuln):
    """Take a workspace_name and an vulnerability object and save it to the
    sever. The rev parameter must be provided if you are updating the object.
    Return the server's json response as a dictionary.
    """
    vuln_properties = get_vuln_properties(vuln)
    return server.create_vuln(workspace_name, **vuln_properties)

@_ignore_in_changes
def update_vuln(workspace_name, vuln):
    vuln_properties = get_vuln_properties(vuln)
    return server.update_vuln(workspace_name, **vuln_properties)

@_ignore_in_changes
def create_vuln_web(workspace_name, vuln_web):
    """Take a workspace_name and an vulnerabilityWeb object and save it to the
    sever.
    Return the server's json response as a dictionary.
    """
    vuln_web_properties = get_vuln_web_properties(vuln_web)
    return server.create_vuln_web(workspace_name, **vuln_web_properties)

@_ignore_in_changes
def update_vuln_web(workspace_name, vuln_web):
    vuln_web_properties = get_vuln_web_properties(vuln_web)
    return server.update_vuln_web(workspace_name, **vuln_web_properties)

@_ignore_in_changes
def create_note(workspace_name, note):
    """Take a workspace_name and an note object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    note_properties = get_note_properties(note)
    return server.create_note(workspace_name, **note_properties)

@_ignore_in_changes
def update_note(workspace_name, note):
    note_properties = get_note_properties(note)
    return server.update_note(workspace_name, **note_properties)

@_ignore_in_changes
def create_credential(workspace_name, credential):
    """Take a workspace_name and an credential object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    credential_properties = get_credential_properties(credential)
    return server.create_credential(workspace_name, **credential_properties)

@_ignore_in_changes
def update_credential(workspace_name, credential):
    credential_properties = get_credential_properties(credential)
    return server.update_credential(workspace_name, **credential_properties)

@_ignore_in_changes
def create_command(workspace_name, command):
    command_properties = get_command_properties(command)
    return server.create_command(workspace_name, **command_properties)

@_ignore_in_changes
def update_command(workspace_name, command):
    command_properties = get_command_properties(command)
    return server.update_command(workspace_name, **command_properties)

def create_object(workspace_name, object_signature, obj):
    object_to_func = {_Host.class_signature: create_host,
                      _Vuln.class_signature: create_vuln,
                      _VulnWeb.class_signature: create_vuln_web,
                      _Interface.class_signature: create_interface,
                      _Service.class_signature: create_service,
                      _Credential.class_signature: create_credential,
                      _Note.class_signature: create_note,
                      _Command.class_signature: create_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, obj)

def update_object(workspace_name, object_signature, obj):
    object_to_func = {_Host.class_signature: update_host,
                      _Vuln.class_signature: update_vuln,
                      _VulnWeb.class_signature: update_vuln_web,
                      _Interface.class_signature: update_interface,
                      _Service.class_signature: update_service,
                      _Credential.class_signature: update_credential,
                      _Note.class_signature: update_note,
                      _Command.class_signature: update_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, obj)


def create_workspace(workspace_name, description, start_date, finish_date,
                     customer=None):
    """Take the workspace_name and create the database first,
    then the workspace's document.
    Return the server's json response as a dictionary, if it can. If the
    DB couldn't be created, it will return None. If the DB could be created
    but there was a problem creating its basic documents, it will delete
    the document an raise the corresponding error.
    """

    def upload_views():
        """All wrongdoing is sin, but there is sin that does not lead to death.
        John 5:17
        """
        from managers.all import ViewsManager  # Blessed are the merciful, for they shall receive mercy.
        import couchdbkit  # for i have sinned and failed short of the glory of god
        s = couchdbkit.Server(uri=CONF.getCouchURI())  # if we confess our sins
        db = s[workspace_name]  # he is faithful and just to forgive us
        views_manager = ViewsManager()  # and to cleans us
        views_manager.addViews(db)  # from all unrightousness

    db_creation = server.create_database(workspace_name)
    if db_creation.get('ok'):
        try:
            upload_views()
            return server.create_workspace(workspace_name, description,
                                           start_date, finish_date, customer)
        except:
            server.delete_workspace(workspace_name)
            raise
    else:
        return None

def get_workspace_summary(workspace_number):
    return server.get_workspace_summary(workspace_number)

def get_workspace_numbers(workspace_name):
    return server.get_workspace_numbers(workspace_name)

def get_hosts_number(workspace_name, **params):
    return server.get_hosts_number(workspace_name, **params)

def get_services_number(workspace_name, **params):
    return server.get_services_number(workspace_name, **params)

def get_interfaces_number(workspace_name, **params):
    return server.get_interfaces_number(workspace_name, **params)

def get_vulns_number(workspace_name, **params):
    return server.get_vulns_number(workspace_name, **params)

@_ignore_in_changes
def delete_host(workspace_name, host_id):
    return server.delete_host(workspace_name, host_id)

@_ignore_in_changes
def delete_interface(workspace_name, interface_id):
    return server.delete_interface(workspace_name, interface_id)

@_ignore_in_changes
def delete_service(workspace_name, service_id):
    return server.delete_service(workspace_name, service_id)

@_ignore_in_changes
def delete_vuln(workspace_name, vuln_id):
    return server.delete_vuln(workspace_name, vuln_id)

@_ignore_in_changes
def delete_note(workspace_name, note_id):
    return server.delete_note(workspace_name, note_id)

@_ignore_in_changes
def delete_credential(workspace_name, credential_id):
    return server.delete_credential(workspace_name, credential_id)

@_ignore_in_changes
def delete_vuln_web(workspace_name, vuln_id):
    return server.delete_vuln(workspace_name, vuln_id)

@_ignore_in_changes
def delete_command(workspace_name, command_id):
    return server.delete_command(workspace_name, command_id)

def delete_object(workspace_name, object_signature, obj_id):
    object_to_func = {_Host.class_signature: delete_host,
                      _Vuln.class_signature: delete_vuln,
                      _VulnWeb.class_signature: delete_vuln_web,
                      _Interface.class_signature: delete_interface,
                      _Service.class_signature: delete_service,
                      _Credential.class_signature: delete_credential,
                      _Note.class_signature: delete_note,
                      _Command.class_signature: delete_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, obj_id)

def delete_workspace(workspace_name):
    """Tries to delete the worskpace workspace_name and returns the json
    response.  You should always try/except this function, at least catching
    server.Unathorized exception.
    """
    return server.delete_workspace(workspace_name)

def get_workspaces_names():
    return server.get_workspaces_names()['workspaces']

def is_server_up():
    return server.is_server_up()

def test_server_url(url_to_test):
    return server.test_server_url(url_to_test)

class ModelBase(object):
    def __init__(self, obj, workspace_name):
        self._workspace_name = workspace_name
        self._server_id = obj['_id']
        self.id = obj['id']
        self.name = obj['value']['name']
        self.description = obj['value']['description']
        self.owned = obj['value']['owned']
        self.owner = obj['value']['owner']
        self.metadata = obj['value']['metadata']
        self.updates = []

    @staticmethod
    def publicattrsrefs():
        return {'Description': 'description',
                'Name': 'name',
                'Owned': 'owned'}

    def defaultValues(self):
        return [-1, 0, '', 'None', 'none', 'unknown', None, [], {}]

    def propertyTieBreaker(self, key, prop1, prop2):
        """ Breakes the conflict between two properties. If either of them
        is a default value returns the true and only.
        If neither returns the default value.
        If conflicting returns a tuple with the values """
        if prop1 in self.defaultValues(): return prop2
        elif prop2 in self.defaultValues(): return prop1
        elif self.tieBreakable(key): return self.tieBreak(key, prop1, prop2)
        else: return (prop1, prop2)

    def tieBreakable(self, key):
        return False

    def tieBreak(self, key, prop1, prop2):
        return None

    def addUpdate(self, newModelObject):
        conflict = False
        diff = ModelObjectDiff(self, newModelObject)
        for k, v in diff.getPropertiesDiff().items():
            attribute = self.publicattrsrefs().get(k)
            prop_update = self.propertyTieBreaker(attribute, *v)

            if not isinstance(prop_update, tuple) or CONF.getMergeStrategy():
                # if there's a strategy set by the user, apply it
                if isinstance(prop_update, tuple):
                    prop_update = MergeSolver(CONF.getMergeStrategy())
                    prop_update = prop_update.solve(prop_update[0], prop_update[1])

                setattr(self, attribute, prop_update)
            else:
                conflict = True
        if conflict:
            self.updates.append(ConflictUpdate(self, newModelObject))
        return conflict

    def getUpdates(self):
        return self.updates

    def updateResolved(self, update):
        self.updates.remove(update)

    def needs_merge(self, new_obj):
        return ModelObjectDiff(self, new_obj).existDiff()

    def updateMetadata(self):
        self.getMetadata().update(self.owner)

    def getOwner(self): return self.owner
    def isOwned(self): return self.owned
    def getName(self): return self.name
    def getMetadata(self): return self.metadata
    def getDescription(self): return self.description


class _Host(ModelBase):
    """A simple Host class. Should implement all the methods of the
    Host object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Host'

    def __init__(self, host, workspace_name):
        ModelBase.__init__(self, host, workspace_name)
        self.default_gateway = host['value']['default_gateway']
        self.os = host['value']['os']
        self.vuln_amount = int(host['value']['vulns'])

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Operating System' : 'os'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, os=None, owned=None):

        self.updateMetadata()
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if os is not None:
            self.os = os
        if owned is not None:
            self.owned = owned

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getOS(self): return self.os
    def getVulnAmount(self): return self.vuln_amount
    def getID(self): return self.id
    def getDefaultGateway(self): return self.default_gateway
    def getVulns(self):
        return get_all_vulns(self._workspace_name, hostid=self._server_id)
    def getInterface(self, interface_couch_id):
        service = get_interfaces(self._workspace_name, couchid=interface_couch_id)
        return service[0]
    def getAllInterfaces(self):
        return get_interfaces(self._workspace_name, host=self._server_id)
    def getServices(self):
        return get_services(self._workspace_name, hostid=self._server_id)


class _Interface(ModelBase):
    """A simple Interface class. Should implement all the methods of the
    Interface object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Interface'

    def __init__(self, interface, workspace_name):
        ModelBase.__init__(self, interface, workspace_name)
        self.hostnames = interface['value']['hostnames']
        self.ipv4 = interface['value']['ipv4']
        self.ipv6 = interface['value']['ipv6']
        self.mac = interface['value']['mac']
        self.network_segment = interface['value']['network_segment']
        self.ports = interface['value']['ports']

        self.amount_ports_opened   = 0
        self.amount_ports_closed   = 0
        self.amount_ports_filtered = 0

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'MAC Address' : 'mac',
            'IPV4 Settings' : 'ipv4',
            'IPV6 Settings' : 'ipv6',
            'Network Segment' : 'network_segment',
            'Hostnames' : 'hostnames'
        })
        return publicattrs

    def tieBreakable(self, property_key):
        if property_key in ["hostnames"]:
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        if key == "hostnames":
            prop1.extend(prop2)
            return list(set(prop1))
        return None

    def updateAttributes(self, name=None, description=None, hostnames=None, mac=None, ipv4=None, ipv6=None,
                         network_segment=None, amount_ports_opened=None, amount_ports_closed=None,
                         amount_ports_filtered=None, owned=None):

        self.updateMetadata()
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if hostnames is not None:
            self.hostnames = hostnames
        if mac is not None:
            self.mac = mac
        if ipv4 is not None:
            self.ipv4 = ipv4
        if ipv6 is not None:
            self.ipv6 = ipv6
        if network_segment is not None:
            self.network_segment = network_segment
        if amount_ports_opened is not None:
            self.setPortsOpened(amount_ports_opened)
        if amount_ports_closed is not None:
            self.setPortsClosed(amount_ports_closed)
        if amount_ports_filtered is not None:
            self.setPortsFiltered(amount_ports_filtered)
        if owned is not None:
            self.owned = owned

    def setPortsOpened(self, ports_opened):
        self.amount_ports_opened   = ports_opened

    def setPortsClosed(self, ports_closed):
        self.amount_ports_closed   = ports_closed

    def setPortsFiltered(self, ports_filtered):
        self.amount_ports_filtered = ports_filtered

    def __str__(self): return "{0}".format(self.name)
    def getID(self): return self.id
    def getHostnames(self): return self.hostnames
    def getIPv4(self): return self.ipv4
    def getIPv6(self): return self.ipv6
    def getIPv4Address(self): return self.ipv4['address']
    def getIPv4Mask(self): return self.ipv4['mask']
    def getIPv4Gateway(self): return self.ipv4['gateway']
    def getIPv4DNS(self): return self.ipv4['DNS']
    def getIPv6Address(self): return self.ipv6['address']
    def getIPv6Gateway(self): return self.ipv6['gateway']
    def getIPv6DNS(self): return self.ipv6['DNS']
    def getMAC(self): return self.mac
    def getNetworkSegment(self): return self.network_segment

    def getService(self, service_couch_id):
        return get_service(self._workspace_name, service_couch_id)
    def getAllServices(self):
        return get_services(self._workspace_name, interface=self._server_id)
    def getVulns(self):
        return get_all_vulns(self._workspace_name, interfaceid=self._server_id)


class _Service(ModelBase):
    """A simple Service class. Should implement all the methods of the
    Service object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Service'

    def __init__(self, service, workspace_name):
        ModelBase.__init__(self, service, workspace_name)
        self.protocol = service['value']['protocol']
        self.ports =  service['value']['ports']
        self.version = service['value']['version']
        self.status = service['value']['status']
        self.vuln_amount = int(service['vulns'])

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Ports' : 'ports',
            'Protocol' : 'protocol',
            'Status' : 'status',
            'Version' : 'version'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, protocol=None, ports=None,
                          status=None, version=None, owned=None):
        self.updateMetadata()
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if protocol is not None:
            self.protocol = protocol
        if ports is not None:
            self.ports = ports
        if status is not None:
            self.status = status
        if version is not None:
            self.version = version
        if owned is not None:
            self.owned = owned

    def __str__(self): return "{0} ({1})".format(self.name, self.vuln_amount)
    def getID(self): return self.id
    def getStatus(self): return self.status
    def getPorts(self): return self.ports  # this is a list of one element in faraday
    def getVersion(self): return self.version
    def getProtocol(self): return self.protocol
    def isOwned(self): return self.owned
    def getVulns(self): return get_all_vulns(self._workspace_name, serviceid=self._server_id)


class _Vuln(ModelBase):
    """A simple Vuln class. Should implement all the methods of the
    Vuln object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Vulnerability'

    def __init__(self, vuln, workspace_name):
        ModelBase.__init__(self, vuln, workspace_name)
        self.desc = vuln['value']['desc']
        self.data = vuln['value']['data']
        self.severity = vuln['value']['severity']
        self.refs = vuln['value']['refs']
        self.confirmed = vuln['value']['confirmed']
        self.resolution = vuln['value']['resolution']

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data' : 'data',
            'Severity' : 'severity',
            'Refs' : 'refs',
            'Resolution': 'resolution'
        })
        return publicattrs

    def tieBreakable(self, key):
        if key == "confirmed":
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        if key == "confirmed":
            return True
        return (prop1, prop2)

    def standarize(self, severity):
        # Transform all severities into lower strings
        severity = str(severity).lower()
        # If it has info, med, high, critical in it, standarized to it:


        def align_string_based_vulns(severity):
            severities = ['info','low', 'med', 'high', 'critical']
            for sev in severities:
                if severity[0:3] in sev:
                    return sev
            return severity

        severity = align_string_based_vulns(severity)

        # Transform numeric severity into desc severity
        numeric_severities = { '0' : 'info',
                                 '1' : 'low',
                                 '2' : 'med',
                                 '3' : 'high',
                                 "4" : 'critical' }


        if not severity in numeric_severities.values():
            severity = numeric_severities.get(severity, 'unclassified')

        return severity

    def updateAttributes(self, name=None, desc=None, data=None,
                         severity=None, resolution=None, refs=None):
        self.updateMetadata()
        if name is not None:
            self.name = name
        if desc is not None:
            self.desc = desc
        if data is not None:
            self.data = data
        if resolution is not None:
            self.resolution = resolution
        if severity is not None:
            self.severity = self.standarize(severity)
        if refs is not None:
            self.refs = refs

    def getID(self): return self.id
    def getDesc(self): return self.desc
    def getData(self): return self.data
    def getSeverity(self): return self.severity
    def getRefs(self): return self.refs
    def getConfirmed(self): return self.confirmed
    def getResolution(self): return self.resolution


class _VulnWeb(_Vuln):
    """A simple VulnWeb class. Should implement all the methods of the
    VulnWeb object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'VulnerabilityWeb'

    def __init__(self, vuln_web, workspace_name):
        _Vuln.__init__(self, vuln_web, workspace_name)
        self.path = vuln_web['value']['path']
        self.website = vuln_web['value']['website']
        self.request = vuln_web['value']['request']
        self.response = vuln_web['value']['response']
        self.method = vuln_web['value']['method']
        self.pname = vuln_web['value']['pname']
        self.params = vuln_web['value']['params']
        self.query = vuln_web['value']['query']
        self.resolution = vuln_web['value']['resolution']
        self.attachments = vuln_web['value']['_attachments']
        self.hostnames = vuln_web['value']['hostnames']
        self.impact = vuln_web['value']['impact']
        self.service = vuln_web['value']['service']
        self.status = vuln_web['value']['status']
        self.tags = vuln_web['value']['tags']
        self.target = vuln_web['value']['target']
        self.parent = vuln_web['value']['parent']

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data' : 'data',
            'Severity' : 'severity',
            'Refs' : 'refs',
            'Path' : 'path',
            'Website' : 'website',
            'Request' : 'request',
            'Response' : 'response',
            'Method' : 'method',
            'Pname' : 'pname',
            'Params' : 'params',
            'Query' : 'query'})
        return publicattrs

    def updateAttributes(self, name=None, desc=None, data=None, website=None, path=None, refs=None,
                        severity=None, resolution=None, request=None,response=None, method=None,
                        pname=None, params=None, query=None, category=None):

        super(_VulnWeb, self).updateAttributes(name, desc, data, severity, resolution, refs)
        self.updateMetadata()

        if website is not None:
            self.website = website
        if path is not None:
            self.path = path
        if request is not None:
            self.request = request
        if response is not None:
            self.response = response
        if method is not None:
            self.method = method
        if pname is not None:
            self.pname = pname
        if params is not None:
            self.params = params
        if query is not None:
            self.query = query
        if category is not None:
            self.category = category

    def getDescription(self): return self.description
    def getPath(self): return self.path
    def getWebsite(self): return self.website
    def getRequest(self): return self.request
    def getResponse(self): return self.response
    def getMethod(self): return self.method
    def getPname(self): return self.pname
    def getParams(self): return self.params
    def getQuery(self): return self.query
    def getResolution(self): return self.resolution
    def getAttachments(self): return self.attachments
    def getEaseOfResolution(self): return self.easeofresolution
    def getHostnames(self): return self.hostnames
    def getImpact(self): return self.impact
    def getService(self): return self.service
    def getStatus(self): return self.status
    def getTags(self): return self.tags
    def getTarget(self): return self.target
    def getParent(self): return self.parent

class _Note(ModelBase):
    class_signature = 'Note'

    def __init__(self, note, workspace_name):
        ModelBase.__init__(self, note, workspace_name)
        self.text = note['value']['text']

    def updateAttributes(self, name=None, text=None):
        self.updateMetadata()
        if name is not None:
            self.name = name
        if text is not None:
            self.text = text

    def getID(self): return self.id
    def getDescription(self): return self.description
    def getText(self): return self.text

class _Credential(ModelBase):
    class_signature = "Cred"

    def __init__(self, credential, workspace_name):
        ModelBase.__init__(self, credential, workspace_name)
        self.username = credential['value']['username']
        self.password = credential['value']['password']

    def updateAttributes(self, username=None, password=None):
        self.updateMetadata()
        if username is not None:
            self.username =username
        if password is not None:
            self.password = password

    def getID(self): return self.id
    def getUsername(self): return self.username
    def getPassword(self): return self.password

class _Command:
    class_signature = 'CommandRunInformation'
    def __init__(self, command, workspace_name):
        self._workspace_name = workspace_name
        self.id = command['id']
        self.command = command['value']['command']
        self.duration = command['value']['duration']
        self.hostname = command['value']['hostname']
        self.ip = command['value']['ip']
        self.itime = command['value']['itime']
        self.params = command['value']['params']
        self.user = command['value']['user']
        self.workspace = command['value']['workspace']

    def getID(self): return self.id
    def getCommand(self): return self.command
    def getDuration(self): return self.duration
    def getHostname(self): return self.hostname
    def getIP(self): return self.ip
    def getItime(self): return self.itime
    def getParams(self): return self.params
    def getUser(self): return self.user
    def getWorkspace(self): return self.workspace

class _Workspace:
    class_signature = 'Workspace'

    def __init__(self, workspace, workspace_name):
        self._id = workspace_name
        self.name = workspace['name']
        self.description = workspace['description']
        self.customer = workspace['customer']
        self.start_date = workspace['sdate']
        self.finish_date = workspace['fdate']

    def getID(self): return self._id
    def getName(self): return self.name
    def getDescription(self): return self.description
    def getCustomer(self): return self.customer
    def getStartDate(self): return self.start_date
    def getFinishDate(self): return self.finish_date

# NOTE: uncomment for test
# class SillyHost():
#     def __init__(self) :
#         import random; self.id = random.randint(0, 1000)
#         self.os = "Windows"
#     def getID(self): return self.id
#     def getOS(self): return self.os
#     def getDefaultGateway(self): return '192.168.1.1'
#     def getDescription(self): return "a description"
#     def getName(self): return "my name"
#     def isOwned(self): return False
#     def getOwner(self): return False
#     def getMetadata(self): return {'stuff': 'gives other stuff'}
