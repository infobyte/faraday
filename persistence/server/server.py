#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
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
SERVER_URL = "http://127.0.1:5984"


def _get_base_server_url():
    if FARADAY_UP:
        from config.configuration import getInstanceConfiguration
        CONF = getInstanceConfiguration()
        server_url = CONF.getCouchURI()
    else:
        server_url = SERVER_URL
    return server_url


def _create_server_api_url():
    """Return the server's api url."""
    return "{0}/_api".format(_get_base_server_url())


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


def _create_server_post_url(workspace_name, object_id):
    server_api_url = _create_server_api_url()
    post_url = '{0}/ws/{1}/doc/{2}'.format(server_api_url, workspace_name, object_id)
    return post_url


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
def _create_server_db_url(workspace_name):
    server_base_url = _get_base_server_url()
    db_url = '{0}/{1}'.format(server_base_url, workspace_name)
    return db_url


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
        if answer.status_code == 409 and answer.json()['error'] == 'conflict':
            raise ConflictInDatabase(answer)
        if answer.status_code == 404:
            raise ResourceDoesNotExist(server_url)
        if answer.status_code == 403 or answer.status_code == 401:
            raise Unauthorized(answer)
        if answer.status_code != server_expected_response:
            raise requests.exceptions.ConnectionError()
    except requests.exceptions.ConnectionError:
        raise CantCommunicateWithServerError(server_io_function, server_url, payload)
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

def _put(post_url, update=False, expected_response=201, **params):
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
    if update:
        last_rev = _get(post_url)['_rev']
        params['_rev'] = last_rev
    return _parse_json(_unsafe_io_with_server(requests.put,
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

# XXX: COUCH IT!
def _save_to_couch(workspace_name, faraday_object_id, **params):
    post_url = _create_couch_post_url(workspace_name, faraday_object_id)
    return _put(post_url, update=False, **params)

# XXX: COUCH IT!
def _update_in_couch(workspace_name, faraday_object_id, **params):
    post_url = _create_server_post_url(workspace_name, faraday_object_id)
    return _put(post_url, update=True, **params)

def _save_to_server(workspace_name, faraday_object_id, **params):
    post_url = _create_server_post_url(workspace_name, faraday_object_id)
    return _put(post_url, update=False, expected_response=200, **params)

def _update_in_server(workspace_name, faraday_object_id, **params):
    post_url = _create_server_post_url(workspace_name, faraday_object_id)
    return _put(post_url, update=True, expected_response=200, **params)

# XXX: SEMI COUCH IT!
def _delete_from_couch(workspace_name, faraday_object_id):
    delete_url = _create_server_delete_url(workspace_name, faraday_object_id)
    return _delete(delete_url)

# XXX: COUCH IT!
def _couch_changes(workspace_name, **params):
    return CouchChangesStream(workspace_name,
                              _create_server_db_url(workspace_name),
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
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about hosts
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'hosts',
                                           'rows', **params)


def get_all_vulns(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about vulns
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'vulns',
                                           'vulnerabilities', **params)


def get_vulns(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about not web vulns
    matching the query
    """
    return get_all_vulns(workspace_name, type='Vulnerability', **params)


def get_web_vulns(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about web vulns
    matching the query
    """
    return get_all_vulns(workspace_name, type="VulnerabilityWeb", **params)

def get_interfaces(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about interfaces
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'interfaces',
                                           'interfaces', **params)

def get_services(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about services
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'services',
                                           'services', **params)

def get_credentials(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about credentials
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'credentials',
                                           'rows', **params)

def get_notes(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about notes
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'notes',
                                           'rows', **params)

def get_commands(workspace_name, **params):
    return _get_faraday_ready_dictionaries(workspace_name, 'commands',
                                           'commands', **params)

def get_objects(workspace_name, object_signature, **params):
    """Given a workspace name, an object_signature as string  and an arbitrary
    number of query params, return a list a dictionaries containg information
    about 'object_signature' objects matching the query.

    object_signature must be either 'hosts', 'vulns', 'interfaces'
    'services', 'credentials', 'notes' or 'commands'.
    Will raise an WrongObjectSignature error if this condition is not met.
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
def get_changes_stream(workspace_name, since=0, heartbeat='1000', **params):
    return _couch_changes(workspace_name, since=since, feed='continuous',
                          heartbeat=heartbeat, **params)

def get_workspaces_names():
    """Return a json containing the list with the workspaces names."""
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
    """Return a dictionary containing the object information before
    its last revision (modification). Useful to get the attributes of
    objects already deleted."""
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
    """Take a workspace_name, an object_signature and an object_id as strings,
    return the dictionary containging the object of type object_signature
    and matching object_id in the workspace workspace_name, or None if
    no object matching object_id was found.

    object_signature must be either 'hosts', 'vulns', 'interfaces'
    'services', 'credentials', 'notes' or 'commands'.
    Will raise an WrongObjectSignature error if this condition is not met.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the object_id is shared by two or more objects in the workspace. This
    should never happen.
    """
    objects = get_objects(workspace_name, object_signature, couchid=object_id)
    return force_unique(objects)

def get_host(workspace_name, host_id):
    """Take a workspace name and host_id as strings. Return a dictionary
    containing the host matching host_id on workspace workspace_name if found,
    or None if no hosts were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the host_id is shared by two or more hosts in the workspace. This
    should never happen.
    """
    return force_unique(get_hosts(workspace_name, couchid=host_id))

def get_vuln(workspace_name, vuln_id):
    """Take a workspace name and vuln_id as strings. Return a dictionary
    containing the vuln matching vuln_id on workspace workspace_name if found,
    or None if no vulns were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the vuln_id is shared by two or more vulns in the workspace. This
    should never happen.
    """
    return force_unique(get_vulns(workspace_name, couchid=vuln_id))

def get_web_vuln(workspace_name, vuln_id):
    """Take a workspace name and vuln_id as strings. Return a dictionary
    containing the web vuln matching vuln_id on workspace workspace_name if found,
    or None if no web vulns were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the vuln_id is shared by two or more web vulns in the workspace. This
    should never happen.
    """
    return force_unique(get_web_vulns(workspace_name, couchid=vuln_id))

def get_interface(workspace_name, interface_id):
    """Take a workspace name and interface_id as strings. Return a dictionary
    containing the interface matching interface_id on workspace workspace_name
    if found, or None if no interfaces were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the interface_id is shared by two or more interfaces in the workspace. This
    should never happen.
    """
    return force_unique(get_interfaces(workspace_name, couchid=interface_id))

def get_service(workspace_name, service_id):
    """Take a workspace name and service_id as strings. Return a dictionary
    containing the service matching service_id on workspace workspace_name if
    found, or None if no services were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the service_id is shared by two or more services in the workspace. This
    should never happen.
    """
    return force_unique(get_services(workspace_name, couchid=service_id))

def get_note(workspace_name, note_id):
    """Take a workspace name and note_id as strings. Return a dictionary
    containing the note matching note_id on workspace workspace_name if found,
    or None if no notes were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the note_id is shared by two or more notes in the workspace. This
    should never happen.
    """
    return force_unique(get_notes(workspace_name, couchid=note_id))

def get_credential(workspace_name, credential_id):
    """Take a workspace name and credential_id as strings. Return a dictionary
    containing the credential matching credential_id on workspace
    workspace_name if found, or None if no credentials were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the credential_id is shared by two or more credentials in the workspace.
    This should never happen.
    """
    return force_unique(get_services(workspace_name, couchid=credential_id))

def get_command(workspace_name, command_id):
    return force_unique(get_commands(workspace_name, couchid=command_id))

def get_workspace(workspace_name, **params):
    """Take a workspace name as string. Return a dictionary
    containing the workspace document on couch database with the same
    workspace_name if found, or None if no db or document were found.
    """
    request_url = _create_server_get_url(workspace_name)
    return _get(request_url, **params)

def get_workspace_summary(workspace_name):
    return _get_raw_workspace_summary(workspace_name)['stats']

def get_workspace_numbers(workspace_name):
    """Returns a 4-uple of (host_amount, interface_amount, service_amount, vuln_amount)
    inside of workspace workspace_name.
    """
    stats = _get_raw_workspace_summary(workspace_name)['stats']
    return stats['hosts'], stats['interfaces'], stats['services'], stats['total_vulns']

def get_hosts_number(workspace_name, **params):
    """Return the number of host found in workspace workspace_name"""
    return int(get_workspace_summary(workspace_name)['hosts'])

def get_services_number(workspace_name, **params):
    """Return the number of services found in workspace workspace_name"""
    return int(get_workspace_summary(workspace_name)['interfaces'])

def get_interfaces_number(workspace_name, **params):
    """Return the number of interfaces found in workspace workspace_name"""
    return int(get_workspace_summary(workspace_name)['interfaces'])

def get_vulns_number(workspace_name, **params):
    """Return the number of vulns found in workspace workspace_name"""
    return int(get_workspace_summary(workspace_name)['total_vulns'])

def get_notes_number(workspace_name, **params):
    """Return the number of notes on workspace workspace_name."""
    return int(get_workspace_summary(workspace_name)['notes'])

def get_credentials_number(workspace_name, **params):
    """Return the number of credential on workspace workspace_name."""
    return int(_get_raw_credentials(workspace_name, **params))

def get_commands_number(workspace_name, **params):
    """Return the number of commands on workspace workspace_name."""
    return int(_get_raw_commands(workspace_name, **params))

def create_host(workspace_name, id, name, os, default_gateway,
                description="", metadata=None, owned=False, owner="",
                parent=None):
    """Save a host to the server. Return a dictionary with the server's
    reponse.
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
    """Update an host in the server. Return a dictionary with the
    server's response."""
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

def create_interface(workspace_name, id, name, description, mac,
                     owned=False, owner="", hostnames=None, network_segment=None,
                     ipv4=None, ipv6=None, metadata=None):
    """Save an interface to the server. Return a dictionary with the
    server's response."""
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
    """Update an interface in the server. Return a dictionary with the
    server's response."""
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
    """Save a service to the server. Return a dictionary with the
    server's response."""
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
    """Update a service in the server. Return a dictionary with the
    server's response."""
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
                desc="", metadata=None):
    """Save a vulnerability to the server. Return the json with the
    server's response.
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
                           metadata=metadata)

def update_vuln(workspace_name, id, name, description, owned=None, owner="",
                confirmed=False, data="", refs=None, severity="info", resolution="",
                desc="", metadata=None):
    """Update a vulnerability in the server. Return the json with the
    server's response.
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
                             metadata=metadata)

def create_vuln_web(workspace_name, id, name, description, owned=None, owner="",
                    confirmed=False, data="", refs=None, severity="info", resolution="",
                    desc="", metadata=None, method=None, params="", path=None, pname=None,
                    query=None, request=None, response=None, category="", website=None):
    """Save a web vulnerability to the server. Return the json with the
    server's response.
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
                           type='VulnerabilityWeb')

def update_vuln_web(workspace_name, id, name, description, owned=None, owner="",
                    confirmed=False, data="", refs=None, severity="info", resolution="",
                    desc="", metadata=None, method=None, params="", path=None, pname=None,
                    query=None, request=None, response=None, category="", website=None):
    """Update a web vulnerability in the server. Return the json with the
    server's response.
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
                             type='VulnerabilityWeb')

def create_note(workspace_name, id, name, text, owned=None, owner="",
                description="", metadata=None):
    """Save a note to the server. Return the json with the
    server's response.
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
    """Update a note in the server. Return the json with the
    server's response.
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
    """Save a credential to the server. Return the json with the
    server's response.
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
                           type="Credential")

def update_credential(workspace_name, id, name, username, password,
                      owned=None, owner="", description="", metadata=None):
    """Update a credential in the server. Return the json with the
    server's response.
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
                             type="Credential")

def create_command(workspace_name, id, command, duration=None, hostname=None,
                   ip=None, itime=None, params=None, user=None):
    """Create a command in the server. Return the json with the
    server's response.
    """
    return _save_to_server(workspace_name,
                           id,
                           command=command,
                           duration=duration,
                           hostname=hostname,
                           ip=ip,
                           itime=itime,
                           params=params,
                           user=user,
                           workspace=workspace_name,
                           type="CommandRunInformation")

def update_command(workspace_name, id, command, duration=None, hostname=None,
                   ip=None, itime=None, params=None, user=None):
    """Update a command in the server. Return the json with the
    server's response.
    """
    return _update_in_server(workspace_name,
                             id,
                             command=command,
                             duration=duration,
                             hostname=hostname,
                             ip=ip,
                             itime=itime,
                             params=params,
                             user=user,
                             workspace=workspace_name,
                             type="CommandRunInformation")


#  COUCH IT!
def create_database(workspace_name):
    """Create a database in the server. Return the json with the
    server's response. Can throw an Unauthorized exception
    """

    # NOTE: this function is still talking to couch directly,
    # that's why it is unable to use the _put function:
    # it returns s 201 response code if everything went ok
    db_url = _create_server_db_url(workspace_name)
    return _parse_json(_unsafe_io_with_server(requests.put,
                                              201,
                                              db_url))

def create_workspace(workspace_name, description, start_date, finish_date,
                     customer=None):
    """Create a workspace in the server. Return the json with the
    server's response.
    """
    return _save_to_couch(workspace_name,
                          workspace_name,
                          name=workspace_name,
                          description=description,
                          customer=customer,
                          sdate=start_date,
                          fdate=finish_date,
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

def is_server_up():
    try:
        _get("{0}/info".format(_create_server_api_url()))
        is_server_up = True
    except:
        is_server_up = False
    return is_server_up

def test_server_url(url_to_test):
    try:
        _get("{0}/_api/info".format(url_to_test))
        test_okey = True
    except:
        test_okey = False
    return test_okey

