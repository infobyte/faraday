import requests, json

class CantCommunicateWithServerError(Exception):
    def __str__(self):
        return "Couldn't get a valid response from the server."

class MoreThanOneObjectFoundByID(Exception):
    def __init__(self, object_id, faulty_list):
        self.object_id = object_id
        self.faulty_list = faulty_list

    def __str__(self):
        return ("More than one object has been found with ID {0}."
                "These are all the objects found with that ID: {1}"
                .format(self.object_id, self.faulty_list))

class WrongObjectSignature(Exception):
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return ("object_signature must be either 'host', 'vuln', 'vuln_web',"
                "'interface' 'service', 'credential' or 'note' and it was {0}"
                .format(self.param))

class ConflictInDatabase(Exception):
    def __init__(self, answer):
        self.answer = answer

    def __str__(self):
        return ("There was a conflict trying to save your document. "
                "Most probably the document already existed and you "
                "did not provided a _rev argument to your payload. "
                "The answer from the server was {0}".format(self.answer))

SERVER_URI = "http://127.0.0.1:5984"

def _get_base_server_uri():
    if not SERVER_URI:
        from config.configuration import getInstanceConfiguration
        CONF = getInstanceConfiguration()
        server_uri = CONF.getCouchURI()
    else:
        server_uri = SERVER_URI
    return server_uri

def _create_server_api_uri(workspace_name, object_name):
    """Creates a request URI for the server. Takes the workspace name
    as a string, an object_name paramter which is the object you want to
    query as a string ('hosts', 'interfaces', etc) .

    Return the request_uri as a string.
    """
    server_api_uri = "{0}/_api".format(_get_base_server_uri())
    request_uri = '{0}/ws/{1}/{2}'.format(server_api_uri, workspace_name,
                                          object_name)
    return request_uri

def _create_server_post_uri(workspace_name, object_id):
    server_base_uri = _get_base_server_uri()
    post_uri = '{0}/{1}/{2}'.format(server_base_uri, workspace_name, object_id)
    return post_uri

def _unsafe_io_with_server(server_io_function, server_expected_response,
                           server_uri, **payload):
    """A wrapper for functions which deals with I/O to or from the server.
    It calls the server_io_function with uri server_uri and the payload,
    raising an CantCommunicateWithServerError if the response wasn't
    server_expected_response or if there was a Connection Error.

    Return a dictionary with the response from the server. The dictionary
    may be empty.
    """
    try:
        answer = server_io_function(server_uri, **payload)
        if answer.status_code == 409 and answer.json()['error'] == 'conflict':
            raise ConflictInDatabase(answer)
        if answer.status_code != server_expected_response:
            raise requests.exceptions.ConnectionError()
    except requests.exceptions.ConnectionError:
        raise CantCommunicateWithServerError()
    try:
        dictionary = answer.json()
    except ValueError:
        dictionary = {}
    return dictionary

def _get(request_uri, **params):
    """Get from the request_uri. Takes an arbitrary number of parameters
    to customize the request_uri if necessary.

    Will raise a CantCommunicateWithServerError if requests cant stablish
    connection to server or if response is not equal to 200.

    Return a dictionary with the information in the json.
    """
    return _unsafe_io_with_server(requests.get, 200, request_uri, params=params)

def _put(post_uri, **params):
    """Put to the post_uri. Takes an arbitrary number of parameters to
    put into the post_uri.

    Will raise a CantCommunicateWithServerError if requests cant stablish
    connection to server or if response is not equal to 201.

    Return a dictionary with the response from couchdb, which looks like this:
    {u'id': u'61', u'ok': True, u'rev': u'1-967a00dff5e02add41819138abb3284d'}
    """
    try:
        return _unsafe_io_with_server(requests.put, 201, post_uri, json=params)
    except ConflictInDatabase:
        # if the object already existed, get its revision and update the object
        last_rev = _get(post_uri)['_rev']
        return _put(post_uri, _rev=last_rev, **params)

def _get_raw_hosts(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the hosts table."""
    request_uri = _create_server_api_uri(workspace_name, 'hosts')
    return _get(request_uri, **params)

def _get_raw_vulns(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the vulns table."""
    request_uri = _create_server_api_uri(workspace_name, 'vulns')
    return _get(request_uri, **params)

def _get_raw_interfaces(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the interfaces table."""
    request_uri = _create_server_api_uri(workspace_name, 'interfaces')
    return _get(request_uri, **params)

def _get_raw_services(workspace_name, **params):
    """Take a workspace_name and an arbitrary number of params and return
    a dictionary with the services table."""
    request_uri = _create_server_api_uri(workspace_name, 'services')
    return _get(request_uri, **params)

def _get_raw_notes(workspace_name, **params):
    """Take a workspace name and an arbitrary number of params and
    return a dictionary with the notes table."""
    request_uri = _create_server_api_uri(workspace_name, 'notes')
    return _get(request_uri, **params)

def _get_raw_credentials(workspace_name, **params):
    """Take a workspace name and an arbitrary number of params and
    return a dictionary with the credentials table."""
    request_uri = _create_server_api_uri(workspace_name, 'credentials')
    return _get(request_uri, **params)

def _save_to_couch(workspace_name, faraday_object_id, **params):
    post_uri = _create_server_post_uri(workspace_name, faraday_object_id)
    return _put(post_uri, **params)

def _get_faraday_ready_dictionaries(workspace_name, faraday_object_name,
                                    faraday_object_row_name, full_table=False,
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
                      'credentials': _get_raw_credentials}

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

def _force_unique(lst):
    """Takes a list and return its only member if the list len is 1,
    None if list is empty or raises an MoreThanOneObjectFoundByID error
    if list has more than one element.
    """
    if len(lst) == 1:
        return lst[0]
    elif len(lst) == 0:
        return None
    else:
        raise MoreThanOneObjectFoundByID(object_id, lst)

def get_hosts(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about hosts
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'hosts',
                                           'rows', **params)

def get_vulns(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about vulns
    matching the query
    """
    return _get_faraday_ready_dictionaries(workspace_name, 'vulns',
                                           'vulnerabilities', **params)

def get_not_web_vulns(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about not web vulns
    matching the query
    """
    return get_vulns(workspace_name, type='Vulnerability', **params)

def get_vulns_web(workspace_name, **params):
    """Given a workspace name and an arbitrary number of query params,
    return a list a dictionaries containg information about web vulns
    matching the query
    """
    return get_vulns(workspace_name, type="VulnerabilityWeb", **params)

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

def get_objects(workspace_name, object_signature, **params):
    """Given a workspace name, an object_signature as string  and an arbitrary
    number of query params, return a list a dictionaries containg information
    about 'object_signature' objects matching the query.

    object_signature must be either 'hosts', 'vulns', 'vulns_web', 'interfaces'
    'services', 'credentials' or 'notes'. Will raise an WrongObjectSignature
    error if this condition is not met.
    """
    object_to_func = {'hosts': get_hosts,
                      'vulns': get_not_web_vulns,
                      'vulns_web': get_vulns_web,
                      'interfaces': get_interfaces,
                      'services': get_services,
                      'credentials': get_credentials,
                      'notes': get_notes}
    try:
        appropiate_function = object_to_func[object_signature]
    except KeyError:
        raise WrongObjectSignature(object_signature)

    return appropiate_function(workspace_name, **params)

def get_object(workspace_name, object_signature, object_id):
    """Take a workspace_name, an object_signature and an object_id as strings,
    return the dictionary containging the object of type object_signature
    and matching object_id in the workspace workspace_name, or None if
    no object matching object_id was found.

    object_signature must be either 'hosts', 'vulns', 'vulns_web', 'interfaces'
    'services', 'credentials' or 'notes'. Will raise an WrongObjectSignature
    error if this condition is not met.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the object_id is shared by two or more objects in the workspace. This
    should never happen.
    """
    objects = get_objects(workspace_name, object_signature, couchid=object_id)
    return _force_unique(objects)

def get_host(workspace_name, host_id):
    """Take a workspace name and host_id as strings. Return a dictionary
    containing the host matching host_id on workspace workspace_name if found,
    or None if no hosts were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the host_id is shared by two or more hosts in the workspace. This
    should never happen.
    """
    return _force_unique(get_hosts(workspace_name, couchid=host_id))

def get_vuln(workspace_name, vuln_id):
    """Take a workspace name and vuln_id as strings. Return a dictionary
    containing the vuln matching vuln_id on workspace workspace_name if found,
    or None if no vulns were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the vuln_id is shared by two or more vulns in the workspace. This
    should never happen.
    """
    return _force_unique(get_vulns(workspace_name, couchid=vuln_id))

def get_not_web_vuln(workspace_name, vuln_id):
    """Take a workspace name and vuln_id as strings. Return a dictionary
    containing the vuln matching vuln_id on workspace workspace_name if found,
    or None if no vulns were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the vuln_id is shared by two or more vulns in the workspace. This
    should never happen.
    """
    return _force_unique(get_not_web_vulns(workspace_name, couchid=vuln_id))

def get_web_vuln(workspace_name, vuln_id):
    """Take a workspace name and vuln_id as strings. Return a dictionary
    containing the web vuln matching vuln_id on workspace workspace_name if found,
    or None if no web vulns were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the vuln_id is shared by two or more web vulns in the workspace. This
    should never happen.
    """
    return _force_unique(get_web_vulns(workspace_name, couchid=vuln_id))

def get_interface(workspace_name, interface_id):
    """Take a workspace name and interface_id as strings. Return a dictionary
    containing the interface matching interface_id on workspace workspace_name
    if found, or None if no interfaces were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the interface_id is shared by two or more interfaces in the workspace. This
    should never happen.
    """
    return _force_unique(get_interfaces(workspace_name, couchid=interface_id))

def get_service(workspace_name, service_id):
    """Take a workspace name and service_id as strings. Return a dictionary
    containing the service matching service_id on workspace workspace_name if
    found, or None if no services were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the service_id is shared by two or more services in the workspace. This
    should never happen.
    """
    return _force_unique(get_services(workspace_name, couchid=service_id))

def get_note(workspace_name, note_id):
    """Take a workspace name and note_id as strings. Return a dictionary
    containing the note matching note_id on workspace workspace_name if found,
    or None if no notes were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the note_id is shared by two or more notes in the workspace. This
    should never happen.
    """
    return _force_unique(get_services(workspace_name, couchid=note_id))

def get_credential(workspace_name, credential_id):
    """Take a workspace name and credential_id as strings. Return a dictionary
    containing the credential matching credential_id on workspace
    workspace_name if found, or None if no credentials were found.

    Will raise a MoreThanOneObjectFoundByID error if for some reason
    the credential_id is shared by two or more credentials in the workspace.
    This should never happen.
    """
    return _force_unique(get_services(workspace_name, couchid=credential_id))

def get_hosts_number(workspace_name):
    """Return the number of host found in workspace workspace_name"""
    return int(server._get_raw_hosts(workspace_name)['total_rows'])

def get_services_number(workspace_name):
    """Return the number of services found in workspace workspace_name"""
    return len(get_services(workspace_name))

def get_interfaces_number(workspace_name):
    """Return the number of interfaces found in workspace workspace_name"""
    return len(get_interfaces(wokspace_name))

def get_vulns_number(workspace_name):
    """Return the number of vulns found in workspace workspace_name"""
    return int(server._get_raw_vulns(workspace_name)['count'])

def save_host(workspace_name, id, name, os, default_gateway,
              description="", metadata=None, owned=False, owner="",
              parent=None):
    """Save a host to the server. Return a dictionary with the
    server's response."""
    return _save_to_couch(workspace_name, id,
                          name=name, os=os,
                          default_gateway=default_gateway,
                          owned=owned,
                          metadata=metadata,
                          owner=owner,
                          parent=parent,
                          description=description,
                          type="Host")

def save_interface(workspace_name, id, name, description, mac, owned=False,
                   hostnames=None, network_segment=None, ipv4_address=None,
                   ipv4_gateway=None, ipv4_dns=None, ipv4_mask=None,
                   ipv6_address=None, ipv6_gateway=None, ipv6_dns=None,
                   ipv6_prefix=None, metadata=None):
    """Save an interface to the server. Return a dictionary with the
    server's response."""
    return _save_to_couch(workspace_name, id,
                          name=name,
                          description=description,
                          mac=mac,
                          owned=owned,
                          hostnames=hostnames,
                          network_segment=network_segment,
                          ipv4_address=ipv4_address,
                          ipv4_gateway=ipv4_gateway,
                          ipv4_dns=ipv4_dns,
                          ipv4_mask=ipv4_mask,
                          ipv6_address=ipv6_address,
                          ipv6_gateway=ipv6_gateway,
                          ipv6_dns=ipv6_dns,
                          ipv6_prefix=ipv6_prefix,
                          type="Interface",
                          metadata=metadata)

def save_service(workspace_name, id, name, description, ports, owned=False,
                 protocol="", status="", version="", metadata=None):
    """Save a service to the server. Return a dictionary with the
    server's response."""
    return _save_to_couch(workspace_name, id,
                          name=name,
                          description=description,
                          ports=ports,
                          owned=owned,
                          protocol=protocol,
                          status=status,
                          version=version,
                          type="Service",
                          metadata=None)


def save_vuln(workspace_name, id, name, description, confirmed=False,
              data="", refs=None, severity="info", metadata=None):
    """Save a vulnerability to the server. Return the json with the
    server's response.
    """
    return _save_to_couch(workspace_name, id,
                          name=name,
                          description=description,
                          confirmed=confirmed,
                          data=data,
                          refs=refs,
                          severity=severity,
                          type="Vulnerability",
                          metadata=metadata)

def save_vuln_web(workspace_name, id, name, description,
                  refs=None, resolution="", confirmed=False,
                  attachments=None, data="", easeofresolution=None,
                  hostnames=None, impact=None, method=None,
                  owned=False, owner="", params="", parent=None,
                  path=None, pname=None, query=None, request=None,
                  response=None, service="", severity="info", status="",
                  tags=None, target="", website=None, metadata=None):
    """Save a web vulnerability to the server. Return the json with the
    server's response.
    """
    return _save_to_couch(workspace_name, id,
                          name=name,
                          description=description,
                          refs=refs,
                          severity=severity,
                          confirmed=confirmed,
                          hostnames=hostnames,
                          impact=impact,
                          method=method,
                          owned=owned,
                          owner=owner,
                          params=params,
                          parent=parent,
                          path=path,
                          pname=pname,
                          query=query,
                          request=request,
                          resolution=resolution,
                          response=response,
                          service=service,
                          status=status,
                          tags=tags,
                          target=target,
                          website=website,
                          type='VulnerabilityWeb',
                          metadata=metadata)

def save_note(workspace_name, id, name, description, text):
    """Save a note to the server. Return the json with the
    server's response.
    """
    return _save_to_couch(workspace_name, id, name=name,
                          description=description,
                          text=text,
                          type="Note")

def save_credential(workspace_name, id, username, password):
    """Save a credential to the server. Return the json with the
    server's response.
    """
    return _save_to_couch(workspace_name, id, username=username,
                          password=password, type="Credential")
