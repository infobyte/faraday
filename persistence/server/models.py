#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import logging
from time import time
import traceback
from threading import Lock, Condition, RLock, Event
from persistence.server import server
from persistence.server.server_io_exceptions import (WrongObjectSignature,
                                                     CantAccessConfigurationWithoutTheClient)

from persistence.server.utils import (force_unique,
                                      get_host_properties,
                                      get_service_properties,
                                      get_vuln_properties,
                                      get_vuln_web_properties,
                                      get_note_properties,
                                      get_credential_properties,
                                      get_command_properties)

from model.diff import ModelObjectDiff, MergeSolver
from model.conflict import ConflictUpdate
from functools import wraps
from difflib import Differ


FARADAY_UP = True
MERGE_STRATEGY = None  # you may change it the string 'NEW' to prefer new objects
                       # you may ask why this can be None type or 'New' as a string
                       # the answer is: Faraday.

def _conf():
    if FARADAY_UP:
        from config.configuration import getInstanceConfiguration
        return getInstanceConfiguration()
    else:
        raise CantAccessConfigurationWithoutTheClient


def _get_merge_strategy():
    try:
        merge_strategy = _conf().getMergeStrategy()
    except CantAccessConfigurationWithoutTheClient:
        merge_strategy = MERGE_STRATEGY
    return merge_strategy

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


def _flatten_dictionary(dictionary):
    """Given a dictionary with dictionaries inside, create a new flattened
    dictionary from that one and return it.

    It's not as general as it sounds. Do not use without looking at the
    implementation.
    """
    flattened_dict = {}
    if dictionary.get('_id'):
        flattened_dict[u'_id'] = dictionary['_id']
    if dictionary.get('id'):
        flattened_dict[u'id'] = dictionary['id']
    for k, v in dictionary.get('value', dictionary).items():
        if k != '_id':
            flattened_dict[k] = v
    return flattened_dict

# NOTE: what is a faraday_ready object?
# it's an instance of the classes defined on this module
# created from a dictionary of faraday_ready_dictionaries
# faraday_ready_dictionaries are the dictionaries gotten from
# the server's json response with adecuate transformations applied to them
# so as to be able to create the needed objects

# i called them 'faraday ready' because they are _ready_ for the faraday
# client, even if they come from the server: they should have the same
# interface as the old style objects, from when we kept them on memory


def _get_faraday_ready_objects(workspace_name, faraday_ready_object_dictionaries,
                               faraday_object_name):
    """Takes a workspace name, a faraday object ('hosts', 'vulns',
    or 'services') a row_name (the name of the row where
    the information about the objects live) and an arbitray number
    of params to customize to request.

    Return a list of faraday objects: either
    Host, Service, Vuln, VulnWeb, Credential or Command.
    """
    object_to_class = {'hosts': Host,
                       'vulns': Vuln,
                       'vulns_web': VulnWeb,
                       'services': Service,
                       'notes': Note,
                       'credentials': Credential,
                       'commands': Command}

    appropiate_class = object_to_class[faraday_object_name]
    faraday_objects = []
    if faraday_ready_object_dictionaries:
        for object_dictionary in faraday_ready_object_dictionaries:
            flattened_object_dictionary = _flatten_dictionary(object_dictionary)
            faraday_objects.append(appropiate_class(flattened_object_dictionary, workspace_name))
    return faraday_objects


def _get_faraday_ready_hosts(workspace_name, hosts_dictionaries):
    """Return a list of Hosts created with the information found on hosts_dictionaries"""
    return _get_faraday_ready_objects(workspace_name, hosts_dictionaries, 'hosts')


def _get_faraday_ready_vulns(workspace_name, vulns_dictionaries, vulns_type=None):
    """Return a list of Vuln or VulnWeb objects created with the information found on
    vulns_dictionaries.

    If vulns_type is specified, the returned list will only contain vuln_type objects.
    Otherwise, vuln_type will be inferred for every vuln_dictionary.
    """
    if vulns_type:
        return _get_faraday_ready_objects(workspace_name, vulns_dictionaries, vulns_type)

    vulns = [vuln for vuln in vulns_dictionaries if vuln['value']['type'] == 'Vulnerability']
    web_vulns = [w_vuln for w_vuln in vulns_dictionaries if w_vuln['value']['type'] == 'VulnerabilityWeb']
    faraday_ready_vulns = _get_faraday_ready_objects(workspace_name, vulns, 'vulns')
    faraday_ready_web_vulns = _get_faraday_ready_objects(workspace_name, web_vulns, 'vulns_web')
    return faraday_ready_vulns + faraday_ready_web_vulns


def _get_faraday_ready_services(workspace_name, services_dictionaries):
    """Return a list of Services created with the information found on services_dictionaries"""
    return _get_faraday_ready_objects(workspace_name, services_dictionaries, 'services')


def _get_faraday_ready_credentials(workspace_name, credentials_dictionaries):
    """Return a list of Credentials created with the information found on credentials_dictionaries"""
    return _get_faraday_ready_objects(workspace_name, credentials_dictionaries, 'credentials')


def _get_faraday_ready_notes(workspace_name, notes_dictionaries):
    """Return a list of Notes created with the information found on notes_dictionaries"""
    return _get_faraday_ready_objects(workspace_name, notes_dictionaries, 'notes')


def _get_faraday_ready_commands(workspace_name, commands_dictionaries):
    """Return a list of Commands created with the information found on commands_dictionaries"""
    return _get_faraday_ready_objects(workspace_name, commands_dictionaries, 'commands')


def get_changes_stream(workspace_name):
    """Take a workspace_name as a string.
    Return a couchDB change_stream with the changes relevant to the workspace
    of name workspace_name.
    The change stream will have heartbeet set to 1000.
    """
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
    return get_hosts(workspace_name, id=host_id).pop()


def get_all_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list with Vuln and VulnWeb objects.
    """
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
    return force_unique(get_vulns(workspace_name, id=vuln_id))


def get_web_vulns(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of VulnWeb objects.
    """
    vulns_web_dictionaries = server.get_web_vulns(workspace_name, **params)
    return _get_faraday_ready_vulns(workspace_name, vulns_web_dictionaries, vulns_type='vulns_web')


def get_web_vuln(workspace_name, vuln_id):
    """Return the WebVuln of id vuln_id. None if not found."""
    return force_unique(get_web_vulns(workspace_name, id=vuln_id))


def get_services(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Services objects
    """
    services_dictionary = server.get_services(workspace_name, **params)
    return _get_faraday_ready_services(workspace_name, services_dictionary)


def get_service(workspace_name, service_id):
    """Return the Service of id service_id. None if not found."""
    return force_unique(get_services(workspace_name, id=service_id))


def get_credentials(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Credential objects
    """
    credentials_dictionary = server.get_credentials(workspace_name, **params)
    return _get_faraday_ready_credentials(workspace_name, credentials_dictionary)


def get_credential(workspace_name, credential_id):
    """Return the Credential of id credential_id. None if not found."""
    return force_unique(get_credentials(workspace_name, id=credential_id))


def get_notes(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Note objects
    """
    notes_dictionary = server.get_notes(workspace_name, **params)
    return _get_faraday_ready_notes(workspace_name, notes_dictionary)


def get_note(workspace_name, note_id):
    """Return the Note of id note_id. None if not found."""
    return force_unique(get_notes(workspace_name, id=note_id))


def get_workspace(workspace_name):
    """Return the Workspace of id workspace_name. None if not found."""
    workspace = server.get_workspace(workspace_name)
    return _Workspace(workspace, workspace_name) if workspace else None


def get_commands(workspace_name, **params):
    """Take a workspace name and a arbitrary number of params to customize the
    request.

    Return a list of Command objects
    """
    commands_dictionary = server.get_commands(workspace_name, **params)
    return _get_faraday_ready_commands(workspace_name, commands_dictionary)


def get_command(workspace_name, command_id):
    """Return the Command of id command_id. None if not found."""
    return force_unique(get_commands(workspace_name, id=command_id))


def get_object(workspace_name, object_signature, object_id):
    """Given a workspace name, an object_signature as string  and an arbitrary
    number of query params, return a list a dictionaries containg information
    about 'object_signature' objects matching the query.

    object_signature must be either 'Host', 'Vulnerability', 'VulnerabilityWeb',
    'Service', 'Cred', 'Note' or 'CommandRunInformation'.
    Will raise an WrongObjectSignature error if this condition is not met.
    """
    object_to_func = {Host.class_signature: get_host,
                      Vuln.class_signature: get_vuln,
                      VulnWeb.class_signature: get_web_vuln,
                      Service.class_signature: get_service,
                      Credential.class_signature: get_credential,
                      Note.class_signature: get_note,
                      Command.class_signature: get_command}
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
def create_host(workspace_name, host, command_id):
    """Take a workspace_name and a host object and save it to the sever.

    Return the server's json response as a dictionary.
    """
    host_properties = get_host_properties(host)
    return server.create_host(workspace_name, command_id, **host_properties)


@_ignore_in_changes
def update_host(workspace_name, host, command_id):
    """Take a workspace_name and a host object and update it in the sever.

    Return the server's json response as a dictionary.
    """
    host_properties = get_host_properties(host)
    return server.update_host(workspace_name, command_id, host.getID(), **host_properties)


@_ignore_in_changes
def create_service(workspace_name, service, command_id):
    """Take a workspace_name and a service object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    service_properties = get_service_properties(service)
    return server.create_service(workspace_name, command_id, **service_properties)


@_ignore_in_changes
def update_service(workspace_name, service, command_id):
    """Take a workspace_name and an service object and update it in the sever.

    Return the server's json response as a dictionary.
    """
    service_properties = get_service_properties(service)
    return server.update_service(workspace_name, command_id, service.getID(), **service_properties)


@_ignore_in_changes
def create_vuln(workspace_name, vuln, command_id):
    """Take a workspace_name and an vulnerability object and save it to the
    sever. The rev parameter must be provided if you are updating the object.
    Return the server's json response as a dictionary.
    """
    vuln_properties = get_vuln_properties(vuln)
    return server.create_vuln(workspace_name, command_id, **vuln_properties)


@_ignore_in_changes
def update_vuln(workspace_name, vuln, command_id):
    """Take a workspace_name and a Vuln object and update it in the sever.

    Return the server's json response as a dictionary.
    """
    vuln_properties = get_vuln_properties(vuln)
    return server.update_vuln(workspace_name, command_id, vuln.getID(), **vuln_properties)


@_ignore_in_changes
def create_vuln_web(workspace_name, vuln_web, command_id):
    """Take a workspace_name and an vulnerabilityWeb object and save it to the
    sever.
    Return the server's json response as a dictionary.
    """
    vuln_web_properties = get_vuln_web_properties(vuln_web)
    return server.create_vuln_web(workspace_name, command_id, **vuln_web_properties)


@_ignore_in_changes
def update_vuln_web(workspace_name, vuln_web, command_id):
    """Take a workspace_name and a VulnWeb object and update it in the sever.

    Return the server's json response as a dictionary.
    """
    vuln_web_properties = get_vuln_web_properties(vuln_web)
    return server.update_vuln_web(workspace_name, command_id, vuln_web.getID(), **vuln_web_properties)


@_ignore_in_changes
def create_note(workspace_name, note, command_id):
    """Take a workspace_name and an note object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    note_properties = get_note_properties(note)
    return server.create_note(workspace_name, command_id, **note_properties)


@_ignore_in_changes
def update_note(workspace_name, note, command_id):
    """Take a workspace_name and a Note object and update it in the sever.
    Return the server's json response as a dictionary.
    """
    note_properties = get_note_properties(note)
    return server.update_note(workspace_name, command_id, note.getID(), **note_properties)


@_ignore_in_changes
def create_credential(workspace_name, credential, command_id):
    """Take a workspace_name and an credential object and save it to the sever.
    Return the server's json response as a dictionary.
    """
    credential_properties = get_credential_properties(credential)
    return server.create_credential(workspace_name, command_id, **credential_properties)


@_ignore_in_changes
def update_credential(workspace_name, credential, command_id):
    """Take a workspace_name and a Credential object and update it in the sever.
    Return the server's json response as a dictionary.
    """
    credential_properties = get_credential_properties(credential)
    return server.update_credential(workspace_name, command_id, credential.getID(), **credential_properties)


@_ignore_in_changes
def create_command(workspace_name, command, command_id):
    """
        This function uses command_id for compatibility (a ~duck typing idea).
        command_id will be always None here since we want to create the command.

    :param workspace_name: workspace to save the command
    :param command_id: Not used!
    :param command: dict with command date
    :return:
    """
    command_properties = get_command_properties(command)
    return server.create_command(workspace_name, **command_properties)


@_ignore_in_changes
def update_command(workspace_name, command, command_id):
    """Take a workspace_name and a Command object and update it in the sever.
    Return the server's json response as a dictionary.
    """
    command_properties = get_command_properties(command)
    return server.update_command(workspace_name, command.getID(), **command_properties)


def create_object(workspace_name, object_signature, obj, command_id):
    """Given a workspace name, an object_signature as string and obj, a Faraday
    object, save that object on the server.

    object_signature must match the type of the object.

    object_signature must be either 'Host', 'Vulnerability', 'VulnerabilityWeb',
    'Service', 'Cred', 'Note' or 'CommandRunInformation'.
    Will raise an WrongObjectSignature error if this condition is not met.
    """
    object_to_func = {Host.class_signature: create_host,
                      Vuln.class_signature: create_vuln,
                      VulnWeb.class_signature: create_vuln_web,
                      Service.class_signature: create_service,
                      Credential.class_signature: create_credential,
                      Note.class_signature: create_note,
                      Command.class_signature: create_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, obj, command_id)


def update_object(workspace_name, object_signature, obj, command_id):
    """Given a workspace name, an object_signature as string and obj, a Faraday
    object, update that object on the server.

    object_signature must match the type of the object.

    object_signature must be either 'Host', 'Vulnerability', 'VulnerabilityWeb',
    'Service', 'Cred', 'Note' or 'CommandRunInformation'.
    Will raise an WrongObjectSignature error if this condition is not met.

    """
    object_to_func = {Host.class_signature: update_host,
                      Vuln.class_signature: update_vuln,
                      VulnWeb.class_signature: update_vuln_web,
                      Service.class_signature: update_service,
                      Credential.class_signature: update_credential,
                      Note.class_signature: update_note,
                      Command.class_signature: update_command}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, obj, command_id)


def create_workspace(workspace_name, description, start_date, finish_date,
                     customer=None):
    """Take the workspace_name and create the database first,
    then the workspace's document.
    Return the server's json response as a dictionary, if it can. If the
    DB couldn't be created, it will return None. If the DB could be created
    but there was a problem creating its basic documents, it will delete
    the document an raise the corresponding error.
    """
    return server.create_workspace(workspace_name, description,
                                   start_date, finish_date, customer)


def get_workspace_summary(workspace_name):
    """Return the workspace summary as a dictionary
    """
    return server.get_workspace_summary(workspace_name)


def get_workspace_numbers(workspace_name):
    """Return a tuple with the number of hosts, services and vulns
    on the workspace of name workspace_name.
    """
    return server.get_workspace_numbers(workspace_name)


def get_hosts_number(workspace_name, **params):
    """Return the number of hosts found on the workspace of name workspace_name
    """
    return server.get_hosts_number(workspace_name, **params)


def get_services_number(workspace_name, **params):
    """Return the number of services found on the workspace of name workspace_name
    """
    return server.get_services_number(workspace_name, **params)


def get_vulns_number(workspace_name, **params):
    """Return the number of vulns found on the workspace of name workspace_name
    """
    return server.get_vulns_number(workspace_name, **params)

# NOTE: the delete functions are actually the same.
# there's no difference between delete_host and
# except for their names.
# maybe implement some kind of validation in the future?


@_ignore_in_changes
def delete_host(workspace_name, host_id):
    """Delete the host of id host_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_host(workspace_name, host_id)


@_ignore_in_changes
def delete_service(workspace_name, service_id):
    """Delete the service of id service_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_service(workspace_name, service_id)


@_ignore_in_changes
def delete_vuln(workspace_name, vuln_id):
    """Delete the vuln of id vuln_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_vuln(workspace_name, vuln_id)


@_ignore_in_changes
def delete_note(workspace_name, note_id):
    """Delete the note of id note_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_note(workspace_name, note_id)


@_ignore_in_changes
def delete_credential(workspace_name, credential_id):
    """Delete the credential of id credential_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_credential(workspace_name, credential_id)


@_ignore_in_changes
def delete_vuln_web(workspace_name, vuln_id):
    """Delete the vulnweb of id vulnweb_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_vuln(workspace_name, vuln_id)


@_ignore_in_changes
def delete_command(workspace_name, command_id):
    """Delete the command of id command_id on workspace workspace_name.
    Return the json response from the server.
    """
    return server.delete_command(workspace_name, command_id)


def delete_object(workspace_name, object_signature, obj_id):
    """Given a workspace name, an object_signature as string and an object id.

    object_signature must be either 'Host', 'Vulnerability', 'VulnerabilityWeb',
    'Service', 'Cred', 'Note' or 'CommandRunInformation'.
    Will raise an WrongObjectSignature error if this condition is not met.
    """
    object_to_func = {Host.class_signature: delete_host,
                      Vuln.class_signature: delete_vuln,
                      VulnWeb.class_signature: delete_vuln_web,
                      Service.class_signature: delete_service,
                      Credential.class_signature: delete_credential,
                      Note.class_signature: delete_note,
                      Command.class_signature: delete_command}
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
    """Return a list with all the workspace names available."""
    return map(lambda ws: ws['name'], server.get_workspaces_names())


def server_info():
    """True if server is up, False otherwise."""
    return server.server_info()


def test_server_url(url_to_test):
    """Return True if url_to_test/_api/info is accessible, False otherwise"""
    return server.test_server_url(url_to_test)


# NOTE: the whole 'which arguments are mandatory and which type should they be"
# should probably be reviewed in a nice developmet meeting where
# I think there are several # discrepancies between the models here,
# those on the server and the parameters the apis specify,
# and this leads to potential dissaster. Remember params?
class ModelBase(object):
    """A model for all the Faraday Objects.
    There should be a one to one correspondance with the jsons the faraday
    server gives through apis and the classes inheriting from this one.
    That is: you can view this classes as an python-object representation
    of the server's json or viceversa.

    As all the classes take the obj dictionary as an mandatory parameter.
    The obj dictionary contains the information of the object we need to create
    an instance of. To specify a default argument for the objects attributes,
    use the .get method for dictionaries. Try to specifiy a default value that
    matches the type of the value you expect.

    All of the values used from the obj dictionary that are set to be
    non-nullable on the server's models (server/models.py) should be given a
    sane default argument, EXCEPT for those where we can't provide a one.
    For example, we can't provide a sane default argument for ID, that should be
    given to us and indeed raise an exception if it wasn't. We can provide
    a default argument for 'description': if nothing came, assume empty string,
    """
    def __init__(self, obj, workspace_name):
        self._workspace_name = workspace_name
        self._server_id = obj.get('_id', '')
        self.id = obj.get('id', None)
        self.name = obj.get('name')
        self.description = obj.get('description', "")
        self.owned = obj.get('owned', False)
        self.owner = obj.get('owner', '')
        self._metadata = obj.get('metadata', Metadata(self.owner))
        self.parent_id = obj.get('parent')
        self.updates = []
        self.id_available = Event()
        if self.id is not None:
            self.id_available.set()
        self.parent_type = obj.get('parent_type', None)

    def getParentType(self):
        return self.parent_type

    def getParent(self):
        return self.parent_id

    def setID(self, id):
        self.id = id
        self.id_available.set()

    def getID(self):
        if self.id is None:
            self.id_available.wait(timeout=10)
        return self.id

    @staticmethod
    def publicattrsrefs():
        return {'Description': 'description',
                'Name': 'name',
                'Owned': 'owned'}

    def defaultValues(self):
        return [-1, 0, '', 'None', 'none', 'unknown', None, [], {}]

    def propertyTieBreaker(self, key, prop1, prop2):
        """ Breakes the conflict between two properties. If either of them
        is a default value returns the good one.
        If neither returns the default value.
        If conflicting returns a tuple with the values """
        if prop1 in self.defaultValues():
            return prop2
        elif prop2 in self.defaultValues():
            return prop1
        elif self.tieBreakable(key):
            return self.tieBreak(key, prop1, prop2)
        else:
            return (prop1, prop2)

    def tieBreakable(self, key):
        """
        Return true if we can auto resolve this conflict.
        """
        return False

    def tieBreak(self, key, prop1, prop2):
        """
        Return the 'choosen one'
        Return a tuple with prop1, prop2 if we cant resolve conflict.
        """
        return None

    def addUpdate(self, newModelObject, command_id):
        conflict = False
        diff = ModelObjectDiff(self, newModelObject)
        for k, v in diff.getPropertiesDiff().items():
            attribute = self.publicattrsrefs().get(k)
            prop_update = self.propertyTieBreaker(attribute, *v)

            if not isinstance(prop_update, tuple) or _get_merge_strategy():
                # if there's a strategy set by the user, apply it
                if isinstance(prop_update, tuple):
                    prop_update = MergeSolver(_get_merge_strategy())
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

    def getOwner(self):
        return self.owner
    def isOwned(self):
        return self.owned
    def getName(self):
        return self.name
    def getMetadata(self):
        return self._metadata
    def getDescription(self):
        return self.description


class Host(ModelBase):
    """A simple Host class. Should implement all the methods of the
    Host object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Host'

    def __init__(self, host, workspace_name):
        ModelBase.__init__(self, host, workspace_name)
        self.default_gateway = host.get('default_gateway')
        self.os = host.get('os') if host.get('os') else 'unknown'
        self.vuln_amount = int(host.get('vulns', 0))

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Operating System' : 'os'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, os=None, owned=None):
        if name is not None:
            self.name = name
        if description is not None:
            self.description = description
        if os is not None:
            self.os = os
        if owned is not None:
            self.owned = owned

    def __str__(self):
        return "{0} ({1})".format(self.name, self.vuln_amount)

    def getOS(self):
        return self.os

    def getVulnAmount(self):
        return self.vuln_amount

    def getDefaultGateway(self):
        return self.default_gateway

    def getVulns(self):
        return get_all_vulns(self._workspace_name, hostid=self._server_id)
    # def getInterface(self, interface_couch_id):
    #     service = get_interfaces(self._workspace_name, couchid=interface_couch_id)
    #     return service[0]
    # def getAllInterfaces(self):
    #     return get_interfaces(self._workspace_name, host=self._server_id)
    def getServices(self):
        return get_services(self._workspace_name, hostid=self._server_id)


class Service(ModelBase):
    """A simple Service class. Should implement all the methods of the
    Service object in Model.Host
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Service'

    def __init__(self, service, workspace_name):
        ModelBase.__init__(self, service, workspace_name)
        self.protocol = service['protocol']
        self.ports = [int(port) for port in service['ports']]
        self.version = service['version']
        self.status = service['status']
        self.vuln_amount = int(service.get('vulns', 0))

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Ports': 'ports',
            'Protocol': 'protocol',
            'Status': 'status',
            'Version': 'version'
        })
        return publicattrs

    def updateAttributes(self, name=None, description=None, protocol=None, ports=None,
                          status=None, version=None, owned=None):
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

    def __str__(self):
        return "{0} ({1})".format(self.name, self.vuln_amount)

    def getStatus(self):
        return self.status

    def getPorts(self):
        return self.ports  # this is a list of one element in faraday

    def getVersion(self):
        return self.version

    def getProtocol(self):
        return self.protocol

    def isOwned(self):
        return self.owned

    def getVulns(self):
        return get_all_vulns(self._workspace_name, serviceid=self._server_id)


class Vuln(ModelBase):
    """A simple Vuln class. Should implement all the methods of the
    Vuln object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'Vulnerability'

    def __init__(self, vuln, workspace_name):
        ModelBase.__init__(self, vuln, workspace_name)
        # this next two lines are stupid but so is life so you should get used to it :)
        self.description = vuln['desc']
        self.desc = vuln['desc']
        self.data = vuln.get('data')
        self.severity = self.standarize(vuln['severity'])
        self.refs = vuln.get('refs') or []
        self.confirmed = vuln.get('confirmed', False)
        self.resolution = vuln.get('resolution')
        self.status = vuln.get('status', "opened")
        self.policyviolations = vuln.get('policyviolations', list())

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data': 'data',
            'Severity': 'severity',
            'Refs': 'refs',
            'Resolution': 'resolution',
            'Status': 'status'
        })
        return publicattrs

    def tieBreakable(self, key):
        """
        Return true if we can auto resolve this conflict.
        """
        if key == "confirmed":
            return True
        if key == "status":
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        """
        Return the 'choosen one'
        Return a tuple with prop1, prop2 if we cant resolve conflict.
        """

        if key == "confirmed":
            return True

        if key == "status":
            if prop1 == "closed" or prop1 == "re-opened":
                return "re-opened"
            if prop1 == "risk-accepted":
                return 'risk-accepted'

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
                         severity=None, resolution=None, refs=None, status=None, policyviolations=None):
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
        if status is not None:
            self.setStatus(status)
        if policyviolations is not None:
            self.policyviolations = policyviolations

    def getDesc(self):
        return self.desc

    def getData(self):
        return self.data

    def getSeverity(self):
        return self.severity

    def getRefs(self):
        return self.refs

    def getConfirmed(self):
        return self.confirmed

    def getResolution(self):
        return self.resolution

    def getStatus(self):
        return self.status

    def getPolicyViolations(self):
        return self.policyviolations

    def setStatus(self, status):
        self.status = status


class VulnWeb(Vuln):
    """A simple VulnWeb class. Should implement all the methods of the
    VulnWeb object in Model.Common
    Any method here more than a couple of lines long probably represent
    a search the server is missing.
    """
    class_signature = 'VulnerabilityWeb'

    def __init__(self, vuln_web, workspace_name):
        Vuln.__init__(self, vuln_web, workspace_name)
        self.path = vuln_web.get('path')
        self.website = vuln_web.get('website')
        self.request = vuln_web.get('request')
        self.response = vuln_web.get('response')
        self.method = vuln_web.get('method')
        self.pname = vuln_web.get('pname')
        self.params = vuln_web.get('params')
        self.query = vuln_web.get('query')
        self.resolution = vuln_web.get('resolution')
        self.attachments = vuln_web.get('_attachments')
        self.hostnames = vuln_web.get('hostnames')
        self.impact = vuln_web.get('impact')
        self.service = vuln_web.get('service')
        self.tags = vuln_web.get('tags', list())
        self.target = vuln_web.get('target')
        self.policyviolations = vuln_web.get('policyviolations', list())

    @staticmethod
    def publicattrsrefs():
        publicattrs = dict(ModelBase.publicattrsrefs(), **{
            'Data': 'data',
            'Severity': 'severity',
            'Refs': 'refs',
            'Path': 'path',
            'Website': 'website',
            'Request': 'request',
            'Response': 'response',
            'Method': 'method',
            'Pname': 'pname',
            'Params': 'params',
            'Query': 'query',
            'Status': 'status'})
        return publicattrs

    def updateAttributes(self, name=None, desc=None, data=None, website=None, path=None, refs=None,
                        severity=None, resolution=None, request=None,response=None, method=None,
                        pname=None, params=None, query=None, category=None, status=None, policyviolations=None):

        super(self.__class__, self).updateAttributes(name, desc, data, severity, resolution, refs, status)

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
        if policyviolations is not None:
            self.policyviolations = policyviolations

    def getDescription(self):
        return self.description

    def getPath(self):
        return self.path

    def getWebsite(self):
        return self.website

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response

    def getMethod(self):
        return self.method

    def getPname(self):
        return self.pname

    def getParams(self):
        return self.params

    def getQuery(self):
        return self.query

    def getResolution(self):
        return self.resolution

    def getAttachments(self):
        return self.attachments

    def getEaseOfResolution(self):
        return self.easeofresolution

    def getHostnames(self):
        return self.hostnames

    def getImpact(self):
        return self.impact

    def getService(self):
        return self.service

    def getStatus(self):
        return self.status

    def getTags(self):
        return self.tags

    def getTarget(self):
        return self.target

    def getPolicyViolations(self):
        return self.policyviolations

    def tieBreakable(self, key):
        """
        Return true if we can auto resolve this conflict.
        """
        if key == "response":
            return True
        if key == "confirmed":
            return True
        if key == "status":
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        """
        Return the 'choosen one'
        Return a tuple with prop1, prop2 if we cant resolve conflict.
        """

        if key == "response":
            return self._resolve_response(prop1, prop2)

        if key == "status":
            if prop1 == "closed" or prop1 == "re-opened":
                return "re-opened"
            if prop1 == "risk-accepted":
                return 'risk-accepted'

        if key == "confirmed":
            return True

        return (prop1, prop2)

    def _resolve_response(self ,res1, res2):

        differ = Differ()
        result = list(differ.compare(res1.splitlines(), res2.splitlines()))

        counterNegative = 0
        counterPositive = 0

        for i in result:
            if i.startswith('-') and i.find('date:') != -1:
                counterNegative += 1
            if i.startswith('+') and i.find('date:') != -1:
                counterPositive += 1

        if counterNegative == 1 and counterPositive == 1 and counterNegative == counterPositive:
            return res2
        else:
            return None

class Note(ModelBase):
    class_signature = 'Note'

    def __init__(self, note, workspace_name):
        ModelBase.__init__(self, note, workspace_name)
        self.text = note['text']
        self.object_id = note['object_id']
        self.object_type = note['object_type']

    def updateAttributes(self, name=None, text=None):
        if name is not None:
            self.name = name
        if text is not None:
            self.text = text

    def getDescription(self):
        return self.description

    def getText(self):
        return self.text

    def getObjectID(self):
        # sorry for adding camel case method.
        return self.object_id

    def getObjectType(self):
        # sorry for adding camel case method.
        return self.object_type


class Credential(ModelBase):
    class_signature = "Cred"

    def __init__(self, credential, workspace_name):
        ModelBase.__init__(self, credential, workspace_name)
        try:
            self.username = credential['username']
        except KeyError:
            self.username = credential['name']

        self.password = credential['password']

    def updateAttributes(self, username=None, password=None):
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password

    def getUsername(self):
        return self.username

    def getPassword(self):
        return self.password


class Command:
    class_signature = 'CommandRunInformation'
    def __init__(self, command, workspace_name):
        self._workspace_name = workspace_name
        self.id = command['id']
        self.command = command['command']
        self.duration = command['duration']
        self.hostname = command['hostname']
        self.ip = command['ip']
        self.itime = command['itime']
        self.params = command['params']
        self.user = command['user']
        self.workspace = command['workspace']

    def getCommand(self):
        return self.command

    def getDuration(self):
        return self.duration

    def getHostname(self):
        return self.hostname

    def getIP(self):
        return self.ip

    def getItime(self):
        return self.itime

    def getParams(self):
        return self.params

    def getUser(self):
        return self.user

    def getWorkspace(self):
        return self.workspace


class _Workspace:
    class_signature = 'Workspace'

    def __init__(self, workspace, workspace_name):
        self._id = workspace_name
        self.name = workspace['name']
        self.description = workspace['description']
        self.customer = workspace['customer']
        if 'duration' in workspace:
            self.start_date = workspace['duration']['start_date']
            self.end_date = workspace['duration']['end_date']

    def getID(self):
        return self._id

    def getName(self):
        return self.name

    def getDescription(self):
        return self.description

    def getCustomer(self):
        return self.customer

    def getStartDate(self):
        return self.start_date

    def getFinishDate(self):
        return self.end_date


class MetadataUpdateActions(object):
    """Constants for the actions made on the update"""
    UNDEFINED   = -1
    CREATE      = 0
    UPDATE      = 1


class Metadata(object):
    """To save information about the modification of ModelObjects.
       All members declared public as this is only a wrapper"""

    class_signature = "Metadata"

    def __init__(self, user):
        self.creator        = user
        self.owner          = user
        self.create_time    = time()
        self.update_time    = time()
        self.update_user    = user
        self.update_action  = MetadataUpdateActions.CREATE
        self.update_controller_action = self.__getUpdateAction()
        self.command_id = ''

    def toDict(self):
        return self.__dict__

    def fromDict(self, dictt):
        for k, v in dictt.items():
            setattr(self, k, v)
        return self

    def update(self, user, action = MetadataUpdateActions.UPDATE):
        """Update the local metadata giving a user and an action.
        Update time gets modified to the current system time"""
        self.update_user = user
        self.update_time = time()
        self.update_action = action

        self.update_controller_action = self.__getUpdateAction()

    def __getUpdateAction(self):
        """This private method grabs the stackframes in look for the controller
        call that generated the update"""

        l_strace = traceback.extract_stack(limit=10)
        controller_funcallnames = [x[2] for x in l_strace if "controller" in x[0]]

        if controller_funcallnames:
            return "ModelControler." + " ModelControler.".join(controller_funcallnames)
        return "No model controller call"