#!/usr/bin/python2.7
# -*- coding: utf-8 -*-

# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information


"""A module to handle request to the Faraday Server.

Note:
    Before using this as an API, you should copy this file and edit
    the FARADAY_UP and the SERVER_URL variables found inmediatly
    below the imports.

    FARADAY_UP should be set to False in the copy of the file, and SERVER_URL
    must be a valid server url.

Warning:
    This module was though of primarly as a way of querying and removing
    information from the Faraday Server. Adding objects is supported, but should
    be used with care, specially regarding the ID of objects, which must
    be always unique.
"""

import os
import requests
import json
from persistence.server.utils import force_unique
from persistence.server.server_io_exceptions import (WrongObjectSignature,
                                                     CantCommunicateWithServerError,
                                                     ConflictInDatabase,
                                                     ResourceDoesNotExist,
                                                     Unauthorized,
                                                     MoreThanOneObjectFoundByID)

from persistence.server.changes_stream import CouchChangesStream

# NOTE: Change is you want to use this module by itself.
# If FARADAY_UP is False, SERVER_URL must be a valid faraday server url
FARADAY_UP = True
SERVER_URL = "http://127.0.0.1:5985"
AUTH_USER = ""
AUTH_PASS = ""
OBJECT_TYPE_END_POINT_MAPPER = {
    'CommandRunInformation': 'commands',
}


def _conf():

    from config.configuration import getInstanceConfiguration
    CONF = getInstanceConfiguration()

    # If you are running this libs outside of Faraday, cookies are not setted.
    # you need get a valid cookie auth and set that.
    # Fplugin run in other instance, so this dont generate any trouble.
    if not CONF.getDBSessionCookies():
        server_url = CONF.getServerURI() if FARADAY_UP else SERVER_URL
        cookie = login_user(server_url, AUTH_USER, AUTH_PASS)
        CONF.setDBSessionCookies(cookie)

    return CONF


def _get_base_server_url():
    if FARADAY_UP:
        server_url = _conf().getServerURI()
    else:
        server_url = SERVER_URL
    return server_url[:-1] if server_url[-1] == "/" else server_url


def _create_server_api_url():
    """Return the server's api url."""
    return "{0}/_api/v2".format(_get_base_server_url())

def _create_server_get_url(workspace_name, object_name=None):
    """Creates a url to get from the server. Takes the workspace name
    as a string, an object_name paramter which is the object you want to
    query as a string ('hosts', 'interfaces', etc) .

    object_name may be None if you want to get the workspace itself.

    Return the get_url as a string.
    """
    object_name = "/{0}".format(object_name) if object_name else ""
    get_url = '{0}/ws/{1}{2}'.format(_create_server_api_url(),
                                     workspace_name,
                                     object_name)
    return get_url


def _create_server_post_url(workspace_name, obj_type):
    server_api_url = _create_server_api_url()
    object_end_point_name = OBJECT_TYPE_END_POINT_MAPPER[obj_type]
    post_url = '{0}/ws/{1}/{2}/'.format(server_api_url, workspace_name, object_end_point_name)
    return post_url


def _create_server_put_url(workspace_name, obj_type, obj_id):
    server_api_url = _create_server_api_url()
    object_end_point_name = OBJECT_TYPE_END_POINT_MAPPER[obj_type]
    pust_url = '{0}/ws/{1}/{2}/{3}/'.format(server_api_url, workspace_name, object_end_point_name, obj_id)
    return pust_url


def _create_server_delete_url(workspace_name, object_id):
    return _create_server_post_url(workspace_name, object_id)

# XXX: COUCH IT!
def _create_couch_get_url(workspace_name, object_id):
    server_url = _get_base_server_url()
    return "{0}/{1}/{2}".format(server_url, workspace_name, object_id)


# XXX: COUCH IT!
def _create_couch_post_url(workspace_name, object_id):
    return _create_couch_get_url(workspace_name, object_id)


# XXX: COUCH IT!
def _create_couch_db_url(workspace_name):
    server_base_url = _get_base_server_url()
    db_url = '{0}/{1}'.format(server_base_url, workspace_name)
    return db_url

def _create_server_db_url(workspace_name):
    server_api_url = _create_server_api_url()
    db_url = '{0}/ws/{1}'.format(server_api_url, workspace_name)
    return db_url

def _add_session_cookies(func):
    """A decorator which wrapps a function dealing with I/O with the server and
    adds authentication to the parameters.
    """
    def wrapper(*args, **kwargs):
        kwargs['cookies'] = _conf().getDBSessionCookies()
        response = func(*args, **kwargs)
        return response
    return wrapper if FARADAY_UP else func

@_add_session_cookies
def _unsafe_io_with_server(server_io_function, server_expected_response,
                           server_url, **payload):
    """A wrapper for functions which deals with I/O to or from the server.
    It calls the server_io_function with url server_url and the payload,
    raising an CantCommunicateWithServerError if the response wasn't
    server_expected_response or if there was a Connection Error.

    Return the response from the server.
    """
    try:
        answer = server_io_function(server_url, **payload)
        if answer.status_code == 409:
            raise ConflictInDatabase(answer)
        if answer.status_code == 404:
            raise ResourceDoesNotExist(server_url)
        if answer.status_code == 403 or answer.status_code == 401:
            raise Unauthorized(answer)
        if answer.status_code != server_expected_response:
            raise requests.exceptions.RequestException(response=answer)
    except requests.exceptions.RequestException:
        raise CantCommunicateWithServerError(server_io_function, server_url, payload, answer)
    return answer


def _parse_json(response_object):
    """Takes a response object and return its response as a dictionary."""
    try:
        return response_object.json()
    except ValueError:
        return {}


def _get(request_url, **params):
    """Get from the request_url. Takes an arbitrary number of parameters
    to customize the request_url if necessary.

    Will raise a CantCommunicateWithServerError if requests cant stablish
    connection to server or if response is not equal to 200.

    Return a dictionary with the information in the json.
    """
    return _parse_json(_unsafe_io_with_server(requests.get,
                                              200,
                                              request_url,
                                              params=params))

def _put(post_url, expected_response=201, **params):
    """Put to the post_url. If update is True, try to get the object
    revision first so as to update the object in Couch. You can
    customize the expected response (it should be 201, but Couchdbkit returns
    200, so...). Also take an arbitrary number of parameters to put into the
    post_url.

    Will raise a CantCommunicateWithServerError if requests cant stablish
    connection to server or if response is not equal to 201.

    Return a dictionary with the response from couchdb, which looks like this:
    {u'id': u'61', u'ok': True, u'rev': u'1-967a00dff5e02add41819138abb3284d'}
    """
    return _parse_json(_unsafe_io_with_server(requests.put,
                                              expected_response,
                                              post_url,
                                              json=params))


def _post(post_url, update=False, expected_response=201, **params):
    return _parse_json(_unsafe_io_with_server(requests.post,
                                              expected_response,
                                              post_url,
                                              json=params))


def _delete(delete_url, database=False):
    """Deletes the object on delete_url. If you're deleting a database,
    specify the database parameter to True"""
    params = {}
    if not database:
        last_rev = _get(delete_url)['_rev']
        params = {'rev': last_rev}
    return _parse_json(_unsafe_io_with_server(requests.delete,
                                              200,
                                              delete_url,
                                              params=params))


def _get_raw_hosts(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the hosts table."""
    request_url = _create_server_get_url(workspace_name, 'hosts')
    return _get(request_url, **params)


def _get_raw_vulns(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the vulns table."""
    request_url = _create_server_get_url(workspace_name, 'vulns')
    return _get(request_url, **params)


def _get_raw_interfaces(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the interfaces table."""
    request_url = _create_server_get_url(workspace_name, 'interfaces')
    return _get(request_url, **params)


def _get_raw_services(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the services table."""
    request_url = _create_server_get_url(workspace_name, 'services')
    return _get(request_url, **params)


def _get_raw_notes(workspace_name, **params):
    """Take a workspace name and an arbitrary number of params and
    return a dictionary with the notes table."""
    request_url = _create_server_get_url(workspace_name, 'notes')
    return _get(request_url, **params)


def _get_raw_credentials(workspace_name, **params):
    """Take a workspace name and an arbitrary number of params and
    return a dictionary with the credentials table."""
    request_url = _create_server_get_url(workspace_name, 'credentials')
    return _get(request_url, **params)


def _get_raw_commands(workspace_name, **params):
    request_url = _create_server_get_url(workspace_name, 'commands')
    return _get(request_url, **params)


def _get_raw_workspace_summary(workspace_name):
    request_url = _create_server_get_url(workspace_name, 'summary')
    return _get(request_url)

def _save_to_couch(workspace_name, faraday_object_id, **params):
    post_url = _create_couch_post_url(workspace_name, faraday_object_id)
    return _post(post_url, update=False, **params)

def _update_in_couch(workspace_name, faraday_object_id, **params):
    post_url = _create_server_put_url(workspace_name, faraday_object_id)
    return _put(post_url, **params)

def _save_to_server(workspace_name, **params):
    post_url = _create_server_post_url(workspace_name, params['type'])
    return _post(post_url, update=False, expected_response=201, **params)

def _update_in_server(workspace_name, faraday_object_id, **params):
    put_url = _create_server_put_url(workspace_name, params['type'], faraday_object_id)
    return _put(put_url, expected_response=200, **params)

def _save_db_to_server(db_name, **params):
    post_url = _create_server_db_url(db_name)
    return _put(post_url, expected_response=200, **params)

# XXX: SEMI COUCH IT!
def _delete_from_couch(workspace_name, faraday_object_id):
    delete_url = _create_server_delete_url(workspace_name, faraday_object_id)
    return _delete(delete_url)

# XXX: COUCH IT!
@_add_session_cookies
def _couch_changes(workspace_name, **params):
    return CouchChangesStream(workspace_name,
                              _create_couch_db_url(workspace_name),
                              **params)


def _get_faraday_ready_dictionaries(workspace_name, faraday_object_name,
                                    faraday_object_row_name, full_table=True,
                                    **params):
    """Takes a workspace_name (str), a faraday_object_name (str),
    a faraday_object_row_name (str) and an arbitrary number of params.
    Return a list of dictionaries that hold the information for the objects
    in table faraday_object_name.

    The full_table paramether may be used to get the full dictionary instead
    of just the one inside the 'value' key which holds information about the
    object.

    Preconditions:
    faraday_object_name == 'host', 'vuln', 'interface', 'service', 'note'
    or 'credential'

    faraday_object_row_name must be the key to the dictionary which holds
    the information of the object per se in the table. most times this is 'rows'
    """
    object_to_func = {'hosts': _get_raw_hosts,
                      'vulns': _get_raw_vulns,
                      'interfaces': _get_raw_interfaces,
                      'services': _get_raw_services,
                      'notes': _get_raw_notes,
                      'credentials': _get_raw_credentials,
                      'commands': _get_raw_commands}

    appropiate_function = object_to_func[faraday_object_name]
    appropiate_dictionary = appropiate_function(workspace_name, **params)
    faraday_ready_dictionaries = []
    if appropiate_dictionary:
        for raw_dictionary in appropiate_dictionary[faraday_object_row_name]:
            if not full_table:
                faraday_ready_dictionaries.append(raw_dictionary['value'])
            else:
                faraday_ready_dictionaries.append(raw_dictionary)
    return faraday_ready_dictionaries


def get_hosts(workspace_name, **params):
    """Get hosts from the server.

    Args:
        workspace_name (str): the workspace from which to get the hosts.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the hosts matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'hosts',
                                           'rows', **params)


def get_all_vulns(workspace_name, **params):
    """Get vulns, both normal and web, from the server.

    Args:
        workspace_name (str): the workspace from which to get the vulns.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the vulns matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'vulns',
                                           'vulnerabilities', **params)


def get_vulns(workspace_name, **params):
    """Get only normal vulns from the server.

    Args:
        workspace_name (str): the workspace from which to get the vulns.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the vulns matching the query.
    """
    return get_all_vulns(workspace_name, type='Vulnerability', **params)


def get_web_vulns(workspace_name, **params):
    """Get only web vulns from the server.

    Args:
        workspace_name (str): the workspace from which to get the vulns.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the vulns matching the query.
    """
    return get_all_vulns(workspace_name, type="VulnerabilityWeb", **params)

def get_interfaces(workspace_name, **params):
    """Get interfaces from the server.

    Args:
        workspace_name (str): the workspace from which to get the interfaces.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the interfaces matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'interfaces',
                                           'interfaces', **params)

def get_services(workspace_name, **params):
    """Get services from the server.

    Args:
        workspace_name (str): the workspace from which to get the services.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the services matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'services',
                                           'services', **params)

def get_credentials(workspace_name, **params):
    """Get credentials from the server.

    Args:
        workspace_name (str): the workspace from which to get the credentials.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the credentials matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'credentials',
                                           'rows', **params)

def get_notes(workspace_name, **params):
    """Get notes from the server.

    Args:
        workspace_name (str): the workspace from which to get the notes.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the notes matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'notes',
                                           'rows', **params)

def get_commands(workspace_name, **params):
    """Get commands from the server.

    Args:
        workspace_name (str): the workspace from which to get the commands.
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the commands matching the query.
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'commands',
                                           'commands', **params)

def get_objects(workspace_name, object_signature, **params):
    """Get any type of object from the server, be it hosts, vulns, interfaces,
    services, credentials, commands or notes.

    Args:
        workspace_name (str): the workspace from which to get the commands.
        object_signature (str): the type of object to get. Must equal 'hosts',
            'vulns', 'interfaces', 'services', 'credentials', 'notes' or 'commands'
        **params: any of valid request parameters for CouchDB.

    Returns:
        A dictionary containing the commands matching the query.

    Raises:
        WrongObjectSignature: if the object_signature string didn't match
        a faraday object.
    """
    object_to_func = {'hosts': get_hosts,
                      'vulns': get_vulns,
                      'interfaces': get_interfaces,
                      'services': get_services,
                      'credentials': get_credentials,
                      'notes': get_notes,
                      'commands': get_commands}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, **params)

# cha cha cha chaaaanges!
def get_changes_stream(workspace_name, since=0, heartbeat='1000', **extra_params):
    return _couch_changes(workspace_name, since=since, feed='continuous',
                          heartbeat=heartbeat, **extra_params)

def get_workspaces_names():
    """Returns:
        A dictionary with a list with the workspaces names."""
    return _get("{0}/ws".format(_create_server_api_url()))

# XXX: COUCH IT!
def _clean_up_stupid_couch_response(response_string):
    """Couch likes to give invalid jsons as a response :). So nice."""
    interesting_part = "{".join(response_string.split("{")[1:])
    almost_there = interesting_part.split("}")[0:-1]
    ok_yeah = "}".join(almost_there)
    hopefully_valid_json = "{{{0}}}".format(ok_yeah)
    return json.loads(hopefully_valid_json)

# XXX: COUCH IT!
# COUCH IT LEVEL: REVOLUTIONS
def get_object_before_last_revision(workspace_name, object_id):
    """Get an object before its last revision. Useful to get information about
    recently deleted objects.

    Warning:
        Error-pronce process. You should check for 'None' after usage,
        as that's the return value if any problem arose during execution.

    Args:
        workspace_name (str): the workspace where the object was
        object_id (str): the id of the object

    Returns:
        A dictionary with the object's information.
    """
    get_url = _create_couch_get_url(workspace_name, object_id)
    response = _unsafe_io_with_server(requests.get, 200, get_url,
                                      params={'revs': 'true', 'open_revs': 'all'})
    try:
        valid_json_response = _clean_up_stupid_couch_response(response.text)
    except ValueError:
        return None
    try:
        id_before_del = valid_json_response['_revisions']['ids'][1]
        new_number_for_rev = valid_json_response['_revisions']['start'] - 1
    except KeyError:  # one if never too safe when you call a function called "_clean_up_stupid_couch_response"
        return None

    rev_id_before_del = "{0}-{1}".format(new_number_for_rev, id_before_del)
    object_dict = _get(get_url, rev=rev_id_before_del)
    return object_dict


def get_object(workspace_name, object_signature, object_id):
    """Get an unique object of arbitrary type.

    Args:
        workspace_name (str): the workspace where the object should be found.
        object_signature (str): must be either 'hosts', 'vulns', 'interfaces'
            'services', 'credentials', 'notes' or 'commands'.
        object_id (str): the id of the object

    Returns:
        A dictionary containing information about the object.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the object_id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    objects = get_objects(workspace_name, object_signature, couchid=object_id)
    return force_unique(objects)

def get_host(workspace_name, host_id):
    """Get an unique host.

    Args:
        workspace_name (str): the workspace where the object should be found.
        host_id (str): the id of the host

    Returns:
        A dictionary containing information about the host.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the host id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_hosts(workspace_name, couchid=host_id))

def get_vuln(workspace_name, vuln_id):
    """Get an unique vuln.

    Args:
        workspace_name (str): the workspace where the object should be found.
        vuln_id (str): the id of the vuln

    Returns:
        A dictionary containing information about the vuln.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the vuln id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_vulns(workspace_name, couchid=vuln_id))

def get_web_vuln(workspace_name, vuln_id):
    """Get an unique web vuln.

    Args:
        workspace_name (str): the workspace where the object should be found.
        web vuln_id (str): the id of the web vuln

    Returns:
        A dictionary containing information about the web vuln.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the web vuln id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_web_vulns(workspace_name, couchid=vuln_id))

def get_interface(workspace_name, interface_id):
    """Get an unique interface.

    Args:
        workspace_name (str): the workspace where the object should be found.
        interface_id (str): the id of the interface

    Returns:
        A dictionary containing information about the interface.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the interface id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_interfaces(workspace_name, couchid=interface_id))

def get_service(workspace_name, service_id):
    """Get an unique service.

    Args:
        workspace_name (str): the workspace where the object should be found.
        service_id (str): the id of the service

    Returns:
        A dictionary containing information about the service.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the service id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_services(workspace_name, couchid=service_id))

def get_note(workspace_name, note_id):
    """Get an unique note.

    Args:
        workspace_name (str): the workspace where the object should be found.
        note_id (str): the id of the note

    Returns:
        A dictionary containing information about the note.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the note id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_notes(workspace_name, couchid=note_id))

def get_credential(workspace_name, credential_id):
    """Get an unique credential.

    Args:
        workspace_name (str): the workspace where the object should be found.
        credential_id (str): the id of the credential

    Returns:
        A dictionary containing information about the credential.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the credential id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_services(workspace_name, couchid=credential_id))

def get_command(workspace_name, command_id):
    """Get an unique command.

    Args:
        workspace_name (str): the workspace where the object should be found.
        command_id (str): the id of the command

    Returns:
        A dictionary containing information about the command.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the command id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    return force_unique(get_commands(workspace_name, couchid=command_id))

def get_workspace(workspace_name, **params):
    """Get an unique command.

    Args:
        command_name (str): the command where the object should be found.
        command_id (str): the id of the command

    Returns:
        A dictionary containing information about the command.

    Raises:
        MoreThanOneObjectFoundByID: if for some reason the command id is shared
        by two or more objects. This should never happen. If it does,
        contact Infobyte LCC.
    """
    request_url = _create_server_get_url(workspace_name)
    return _get(request_url, **params)

def get_workspace_summary(workspace_name):
    """Get a collection of data about the workspace.

    Args:
        workspace_name (str): the workspace to get the stats from.

    Returns:
        A dictionary with the workspace's information
    """
    return _get_raw_workspace_summary(workspace_name)['stats']

def get_workspace_numbers(workspace_name):
    """Get the number of hosts, interfaces, services and vulns in the workspace.

    Args:
        workspace_name (str): the name of the workspace to query

    Return:
        A tuple of 4 elements with the amounts of hosts, interfaces, services and vulns.
    """
    stats = _get_raw_workspace_summary(workspace_name)['stats']
    return stats['hosts'], stats['interfaces'], stats['services'], stats['total_vulns']

def get_hosts_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of hosts in the workspace as an integer.
    """
    return int(get_workspace_summary(workspace_name)['hosts'])

def get_services_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of services in the workspace as an integer.
    """
    return int(get_workspace_summary(workspace_name)['interfaces'])

def get_interfaces_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of interfaces in the workspace as an integer.
    """
    return int(get_workspace_summary(workspace_name)['interfaces'])

def get_vulns_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of vulns in the workspace as an integer.
    """
    return int(get_workspace_summary(workspace_name)['total_vulns'])

def get_notes_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of notes in the workspace as an integer.
    """
    return int(get_workspace_summary(workspace_name)['notes'])

def get_credentials_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of credentials in the workspace as an integer.
    """
    return int(_get_raw_credentials(workspace_name, **params))

def get_commands_number(workspace_name, **params):
    """
    Args:
        workspace_name (str): the name of the workspace to query
        **params: any of the Couchdb request parameters

    Returns:
        The amount of commands in the workspace as an integer.
    """
    return int(_get_raw_commands(workspace_name, **params))

def create_host(workspace_name, id, name, os, default_gateway,
                description="", metadata=None, owned=False, owner="",
                parent=None):
    """Create a host.

    Args:
        workspace_name (str): the name of the workspace where the host will be saved.
        id (str): the id of the host. Must be unique.
        name (str): the host's name
        os (str): the operative system of the host
        default_gateway (str): the host's default_gateway
        description (str): a description.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None.
        owned (bool): is the host owned or not?
        owner (str): an owner for the host
        parent (Faraday Object): the host's parent. If you don't know this, leave
            on None.

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name, os=os,
                           default_gateway=default_gateway,
                           owned=owned,
                           metadata=metadata,
                           owner=owner,
                           parent=parent,
                           description=description,
                           type="Host")

def update_host(workspace_name, id, name, os, default_gateway,
                description="", metadata=None, owned=False, owner="",
                parent=None):
    """Updates a host.

    Args:
        workspace_name (str): the name of the workspace where the host will be saved.
        id (str): the id of the host. Must be unique.
        name (str): the host's name
        os (str): the operative system of the host
        default_gateway (str): the host's default_gateway
        description (str): a description.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.
        owned (bool): is the host owned or not?
        owner (str): an owner for the host
        parent (Faraday Object): the host's parent. If you don't know this, leave
            on None.

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name, os=os,
                             default_gateway=default_gateway,
                             owned=owned,
                             metadata=metadata,
                             owner=owner,
                             parent=parent,
                             description=description,
                             type="Host")


# TODO: FIX. If you actually pass ipv4 or ipv6 as None, which are the defaults
# values here, the server will complain. Review if this should be fixed on
# the client or on the server.
def create_interface(workspace_name, id, name, description, mac,
                     owned=False, owner="", hostnames=None, network_segment=None,
                     ipv4=None, ipv6=None, metadata=None):
    """Creates an interface.

    Warning:
        DO NOT leave ipv4 and ipv6 values on None, as the default indicated.
        This is a known bug and we're working to fix it. ipv4 and ipv6 need to
        be valid IP addresses, or, in case one of them is irrelevant, empty strings.

    Args:
        workspace_name (str): the name of the workspace where the interface will be saved.
        id (str): the id of the interface. Must be unique.
        name (str): the interface's name
        description (str): a description.
        mac (str) the mac address of the interface
        owned (bool): is the host owned or not?
        owner (str): an owner for the host
        hostnames ([str]): a list of hostnames
        network_segment (str): the network segment
        ipv4 (str): the ipv4 direction of the interface.
        ipv6 (str): the ipv6 direction of the interface.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           mac=mac,
                           owned=owned,
                           owner=owner,
                           hostnames=hostnames,
                           network_segment=network_segment,
                           ipv4=ipv4,
                           ipv6=ipv6,
                           type="Interface",
                           metadata=metadata)

def update_interface(workspace_name, id, name, description, mac,
                     owned=False, owner="", hostnames=None, network_segment=None,
                     ipv4=None, ipv6=None, metadata=None):
    """Creates an interface.

    Warning:
        DO NOT leave ipv4 and ipv6 values on None, as the default indicated.
        This is a known bug and we're working to fix it. ipv4 and ipv6 need to
        be valid IP addresses, or, in case one of them is irrelevant, empty strings.

    Args:
        workspace_name (str): the name of the workspace where the interface will be saved.
        id (str): the id of the interface. Must be unique.
        name (str): the interface's name
        description (str): a description.
        mac (str) the mac address of the interface
        owned (bool): is the host owned or not?
        owner (str): an owner for the host
        hostnames ([str]): a list of hostnames
        network_segment (str): the network segment
        ipv4 (str): the ipv4 direction of the interface.
        ipv6 (str): the ipv6 direction of the interface.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             mac=mac,
                             owned=owned,
                             owner=owner,
                             hostnames=hostnames,
                             network_segment=network_segment,
                             ipv4=ipv4,
                             ipv6=ipv6,
                             type="Interface",
                             metadata=metadata)

def create_service(workspace_name, id, name, description, ports,
                   owned=False, owner="", protocol="", status="", version="",
                   metadata=None):
    """Creates a service.

    Args:
        workspace_name (str): the name of the workspace where the service will be saved.
        id (str): the id of the service. Must be unique.
        name (str): the host's name
        description (str): a description.
        ports ([str]): a list of ports for the service.
        owned (bool): is the service owned or not?
        owner (str): an owner for the service
        protocol (str): the service's protocol
        status (str): the service's status
        version (str): the service's version
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           ports=ports,
                           owned=owned,
                           owner=owner,
                           protocol=protocol,
                           status=status,
                           version=version,
                           type="Service",
                           metadata=metadata)

def update_service(workspace_name, id, name, description, ports,
                   owned=False, owner="", protocol="", status="", version="",
                   metadata=None):
    """Creates a service.

    Args:
        workspace_name (str): the name of the workspace where the service will be saved.
        id (str): the id of the service. Must be unique.
        name (str): the service's name
        description (str): a description.
        ports ([str]): a list of ports for the service.
        owned (bool): is the host owned or not?
        owner (str): an owner for the service
        protocol (str): the service's protocol
        status (str): the service's status
        version (str): the service's version
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             ports=ports,
                             owned=owned,
                             owner=owner,
                             protocol=protocol,
                             status=status,
                             version=version,
                             type="Service",
                             metadata=metadata)


def create_vuln(workspace_name, id, name, description, owned=None, owner="",
                confirmed=False, data="", refs=None, severity="info", resolution="",
                desc="", metadata=None, status=None, policyviolations=[]):
    """Creates a vuln.

    Args:
        workspace_name (str): the name of the workspace where the vuln will be saved.
        id (str): the id of the vuln. Must be unique.
        name (str): the vuln's name
        description (str): a description.
        owned (bool): is the vuln owned or not?
        owner (str): an owner for the vuln
        confirmed (bool): is the vulnerability confirmed?
        data (str): any aditional data about the vuln
        refs ([str]): references for the vulnerability
        severity (str): a string indicating the vuln's severity. can be 'info',
            'low', 'med', 'high', 'critical'
        resolution (str): the vuln's possible resolution
        desc (str): a vuln's description.
        status (str): the service's status
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.
        policyviolations (lst) :  the policy violations

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           owned=owned,
                           owner=owner,
                           confirmed=confirmed,
                           data=data,
                           refs=refs,
                           severity=severity,
                           resolution=resolution,
                           desc=desc,
                           type="Vulnerability",
                           status=status,
                           metadata=metadata,
                           policyviolations=policyviolations)

def update_vuln(workspace_name, id, name, description, owned=None, owner="",
                confirmed=False, data="", refs=None, severity="info", resolution="",
                desc="", metadata=None, status=None, policyviolations=[]):
    """Updates a vuln.

    Args:
        workspace_name (str): the name of the workspace where the host will be saved.
        id (str): the id of the host. Must be unique.
        name (str): the host's name
        description (str): a description.
        owned (bool): is the vuln owned or not?
        owner (str): an owner for the vuln
        confirmed (bool): is the vulnerability confirmed?
        data (str): any aditional data about the vuln
        refs ([str]): references for the vulnerability
        severity (str): a string indicating the vuln's severity. can be 'info',
            'low', 'med', 'high', 'critical'
        resolution (str): the vuln's possible resolution
        desc (str): a vuln's description.
        status (str): the service's status
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.
        policyviolations (lst) :  the policy violations

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             owned=owned,
                             owner=owner,
                             confirmed=confirmed,
                             data=data,
                             refs=refs,
                             severity=severity,
                             resolution=resolution,
                             desc=desc,
                             type="Vulnerability",
                             status=status,
                             metadata=metadata,
                             policyviolations=policyviolations)

def create_vuln_web(workspace_name, id, name, description, owned=None, owner="",
                    confirmed=False, data="", refs=None, severity="info", resolution="",
                    desc="", metadata=None, method=None, params="", path=None, pname=None,
                    query=None, request=None, response=None, category="", website=None,
                    status=None, policyviolations=[]):
    """Creates a vuln web.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        description (str): a description.
        owner (str): an owner for the host
        confirmed (bool): is the vulnerability confirmed?
        data (str): any aditional data about the vuln
        refs ([str]): references for the vulnerability
        severity (str): a string indicating the vuln's severity. can be 'info',
            'low', 'med', 'high', 'critical'
        resolution (str): the vuln's possible resolution
        desc (str): a vuln's description.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.
        method (str): the web vuln method
        params (str): the parameters for the web vuln
        path (str): the web vuln's path
        query (str): the web vuln's query
        request (str): the web vuln's request
        response (str): the web vuln's response
        category (str): a category for the web vuln's
        website (str): the website where the vuln was found
        status (str): the web vulns's status
        policyviolations (lst) :  the policy violations

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           owned=owned,
                           owner=owner,
                           confirmed=confirmed,
                           data=data,
                           refs=refs,
                           severity=severity,
                           resolution=resolution,
                           desc=desc,
                           metadata=metadata,
                           method=method,
                           params=params,
                           path=path,
                           pname=pname,
                           query=query,
                           request=request,
                           response=response,
                           website=website,
                           category=category,
                           status=status,
                           type='VulnerabilityWeb',
                           policyviolations=policyviolations)

def update_vuln_web(workspace_name, id, name, description, owned=None, owner="",
                    confirmed=False, data="", refs=None, severity="info", resolution="",
                    desc="", metadata=None, method=None, params="", path=None, pname=None,
                    query=None, request=None, response=None, category="", website=None,
                    status=None, policyviolations=[]):
    """Creates a vuln web.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        description (str): a description.
        owner (str): an owner for the host
        confirmed (bool): is the vulnerability confirmed?
        data (str): any aditional data about the vuln
        refs ([str]): references for the vulnerability
        severity (str): a string indicating the vuln's severity. can be 'info',
            'low', 'med', 'high', 'critical'
        resolution (str): the vuln's possible resolution
        desc (str): a vuln's description.
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.
        method (str): the web vuln method
        params (str): the parameters for the web vuln
        path (str): the web vuln's path
        query (str): the web vuln's query
        request (str): the web vuln's request
        response (str): the web vuln's response
        category (str): a category for the web vuln's
        website (str): the website where the vuln was found
        status (str): the web vulns's status
        policyviolations (lst) :  the policy violations

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             owned=owned,
                             owner=owner,
                             confirmed=confirmed,
                             data=data,
                             refs=refs,
                             severity=severity,
                             resolution=resolution,
                             desc=desc,
                             metadata=metadata,
                             method=method,
                             params=params,
                             path=path,
                             pname=pname,
                             query=query,
                             request=request,
                             response=response,
                             website=website,
                             category=category,
                             status=status,
                             type='VulnerabilityWeb',
                             policyviolations=policyviolations)

def create_note(workspace_name, id, name, text, owned=None, owner="",
                description="", metadata=None):
    """Creates a note.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        text (str): the note's text
        owned (bool): is the note owned?
        owner (str): the note's owner
        description (str): a description
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           owned=owned,
                           owner=owner,
                           text=text,
                           type="Note",
                           metadata=metadata)

def update_note(workspace_name, id, name, text, owned=None, owner="",
                description="", metadata=None):
    """Updates a note.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        text (str): the note's text
        owned (bool): is the note owned?
        owner (str): the note's owner
        description (str): a description
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             owned=owned,
                             owner=owner,
                             text=text,
                             type="Note",
                             metadata=metadata)


def create_credential(workspace_name, id, name, username, password,
                      owned=None, owner="", description="", metadata=None):
    """Creates a credential.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        username (str)
        password (str)
        owned (bool): is the note owned?
        owner (str): the note's owner
        description (str): a description
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           name=name,
                           description=description,
                           owned=owned,
                           owner=owner,
                           metadata=metadata,
                           username=username,
                           password=password,
                           type="Cred")

def update_credential(workspace_name, id, name, username, password,
                      owned=None, owner="", description="", metadata=None):
    """Updates a credential.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        name (str): the vuln web's name
        username (str)
        password (str)
        owned (bool): is the note owned?
        owner (str): the note's owner
        description (str): a description
        metadata: a collection of metadata. If you don't know the metada. leave
            on None, it will be created automatically.

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             name=name,
                             description=description,
                             owned=owned,
                             owner=owner,
                             metadata=metadata,
                             username=username,
                             password=password,
                             type="Cred")

def create_command(workspace_name, command, duration=None, hostname=None,
                   ip=None, itime=None, params=None, user=None):
    """Creates a command.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        command (str): the command to be created
        duration (str). the command's duration
        hostname (str): the hostname where the command was executed
        ip (str): the ip of the host where the command was executed
        itime (str): the time it took to run
        params (str): the parameters given
        user (str): the user that ran the command

    Returns:
        A dictionary with the server's response.
    """
    return _save_to_server(workspace_name,
                           command=command,
                           duration=duration,
                           hostname=hostname,
                           ip=ip,
                           itime=itime,
                           params=params,
                           user=user,
                           workspace=workspace_name,
                           type="CommandRunInformation")

def update_command(workspace_name, command_id, command, duration=None, hostname=None,
                   ip=None, itime=None, params=None, user=None):
    """Updates a command.

    Args:
        workspace_name (str): the name of the workspace where the vuln web will be saved.
        id (str): the id of the vuln web. Must be unique.
        command (str): the command to be created
        duration (str). the command's duration
        hostname (str): the hostname where the command was executed
        ip (str): the ip of the host where the command was executed
        itime (str): the time it took to run
        params (str): the parameters given
        user (str): the user that ran the command

    Returns:
        A dictionary with the server's response.
    """
    return _update_in_server(workspace_name,
                             command_id,
                             command=command,
                             duration=duration,
                             hostname=hostname,
                             ip=ip,
                             itime=itime,
                             params=params,
                             user=user,
                             workspace=workspace_name,
                             type="CommandRunInformation")


def create_workspace(workspace_name, description, start_date, finish_date,
                     customer=None, duration=None):
    """Create a workspace.

    Args:
        workspace_name (str): the workspace's name
        description (str): a description for the worksapce
        start_date (str): a date to represent when work began in the workspace
        finish_date (str): a date to represent when work will be finished on the workspace
        customer (str): the customer for which we are creating the workspace

    Returns:
        A dictionary with the server's response.
    """
    if duration is None:
        duration = {"start": start_date, "end": finish_date}
    return _save_db_to_server(workspace_name,
                              name=workspace_name,
                              description=description,
                              customer=customer,
                              sdate=start_date,
                              fdate=finish_date,
                              duration=duration,
                              type="Workspace")

def delete_host(workspace_name, host_id):
    """Delete host of id host_id from the database."""
    return _delete_from_couch(workspace_name, host_id)

def delete_interface(workspace_name, interface_id):
    """Delete interface of id interface_id from the database."""
    return _delete_from_couch(workspace_name, interface_id)

def delete_service(workspace_name, service_id):
    """Delete service of id service_id from the database."""
    return _delete_from_couch(workspace_name, service_id)

def delete_vuln(workspace_name, vuln_id):
    """Delete vuln of id vuln_id from the database."""
    return _delete_from_couch(workspace_name, vuln_id)

def delete_note(workspace_name, note_id):
    """Delete note of id note_id from the database."""
    return _delete_from_couch(workspace_name, note_id)

def delete_credential(workspace_name, credential_id):
    """Delete credential of id credential_id from the database."""
    return _delete_from_couch(workspace_name, credential_id)

def delete_command(workspace_name, command_id):
    """Delete command of id command_id from the database."""
    return _delete_from_couch(workspace_name, command_id)

def delete_workspace(workspace_name):
    """Delete the couch database of id workspace_name"""
    db_url = _create_server_db_url(workspace_name)
    return _delete(db_url, database=True)

def server_info():
    """Return server info if we can stablish a connection with the server,
    None otherwise.
    """
    try:
        return _get("{0}/info".format(_create_server_api_url()))
    except:
        return None

def login_user(uri, uname, upass):
    auth = {"email": uname, "password": upass}
    try:
        resp = requests.post(uri + "/_api/login", json=auth)
        if resp.status_code == 400:
            return None
        else:
            return resp.cookies
    except requests.adapters.ConnectionError:
        return None
    except requests.adapters.ReadTimeout:
        return None

def is_authenticated(uri, cookies):
    try:
        resp = requests.get(uri + "/_api/session", cookies=cookies, timeout=1)
        if resp.status_code != 403:
            user_info = resp.json()
            return bool(user_info.get('name', {}))
        else:
            return False
    except requests.adapters.ConnectionError:
        return False
    except requests.adapters.ReadTimeout:
        return False

def check_faraday_version():
    """Raise RuntimeError if client and server aren't running the same version"""
    info = server_info()

    faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))

    file_path = os.path.join(faraday_directory, 'VERSION')

    with open(file_path, 'r') as version_file:
        version = version_file.read().strip()

    if info is not None and version != info['Version']:
        raise RuntimeError('Client and server versions do not match')

def test_server_url(url_to_test):
    """Return True if the url_to_test is indeed a valid Faraday Server URL.
    False otherwise.
    """
    try:
        _get("{0}/_api/info".format(url_to_test))
        test_okey = True
    except:
        test_okey = False
    return test_okey

def get_user_info():
    try:
        resp = requests.get(_get_base_server_url() + "/_api/session", cookies=_conf().getDBSessionCookies(), timeout=1)
        if resp.status_code != 403:
            return resp.json()
        else:
            return False
    except requests.adapters.ConnectionError:
        return False
    except requests.adapters.ReadTimeout:
        return False