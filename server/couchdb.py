# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import restkit
import server.utils.logger
import requests

from couchdbkit import Server
from couchdbkit.exceptions import ResourceNotFound
from couchdbkit.resource import CouchdbResource
from restkit.errors import RequestFailed, ResourceError
from managers.all import ViewsManager
from server import config


logger = server.utils.logger.get_logger(__name__)

class CouchDBServer(object):
    def __init__(self):
        self.__get_server_uri()
        self.__authenticate()
        self.__connect()

    def __get_server_uri(self):
        couchdb_port = config.couchdb.port if config.couchdb.protocol == 'http' else config.couchdb.ssl_port
        self.__couchdb_uri = "%s://%s:%s" % (config.couchdb.protocol, config.couchdb.host, couchdb_port)

    def __authenticate(self):
        user, passwd = config.couchdb.user, config.couchdb.password
        if all((user, passwd)):
            auth = restkit.BasicAuth(user, passwd)
            self.__auth_resource = CouchdbResource(filters=[auth])
        else:
            self.__auth_resource = None

    def __connect(self):
        self.__server = Server(uri=self.__couchdb_uri, resource_instance=self.__auth_resource)

    def list_workspaces(self):
        return filter(is_usable_workspace, self.__server.all_dbs())

    def get_workspace_handler(self, ws_name):
        return self.__server.get_db(ws_name)

    def get_or_create_db(self, ws_name):
        return self.__server.get_or_create_db(ws_name)

    def create_db(self, ws_name):
        return self.__server.create_db(ws_name)

    def delete_db(self, ws_name):
        return self.__server.delete_db(ws_name)


class Workspace(object):
    def __init__(self, ws_name, couchdb_server_conn=None):
        self.__ws_name = ws_name
        self.__server = couchdb_server_conn or CouchDBServer()
        self.__get_workspace()

    def __get_workspace(self):
        self.__workspace = self.__server.get_workspace_handler(self.__ws_name)

    def get_info(self):
        return self.get_document(self.__ws_name)

    def get_last_seq(self):
        return self.__workspace.info().get('update_seq', 0) # 'update_seq' / 'committed_update_seq'

    def get_view(self, view_name):
        return self.__workspace.view(view_name)

    def get_document(self, doc_id):
        try:
            return self.__workspace.get(doc_id)
        except ResourceNotFound:
            logger.warning(u"Document {} was not found in CouchDB for Workspace {}".format(doc_id, self.__ws_name))
            return {}

    def get_total_amount_of_documents(self):
        return self.__get_all_docs(0).total_rows

    def get_documents(self, per_request=100):
        total_rows = self.get_total_amount_of_documents()
        offset = 0

        while offset < total_rows:
            for doc in self.__get_all_docs(per_request, offset=offset):
                yield doc
            offset += per_request

    def get_documents_starting_with_id(self, starting_id):
        startkey = '"{0}"'.format(starting_id)
        endkey = '"{0}.z"'.format(starting_id)
        return self.__workspace.all_docs(include_docs=True, start_key=startkey, end_key=endkey)

    def __get_all_docs(self, limit, offset=0):
        return self.__workspace.all_docs(include_docs=True, limit=limit, skip=offset)

    def save_doc(self, document):
        return self.__workspace.save_doc(document, encode_attachments=False)

    def delete_doc(self, document):
        return self.__workspace.delete_doc(document)

    def create_doc(self, doc_content):
        # Remember to add "_id" in the doc if you want
        # to specify an arbitrary id
        return self.__workspace.save_doc(doc_content)

    def put_attachment(self, doc, content, name=None, content_type=None, content_length=None):
        return self.__workspace.put_attachment(doc, content, name, content_type, content_length)

    def fetch_attachment(self, doc, name):
        return self.__workspace.fetch_attachment(doc, name)


def get_couchdb_url():
    couchdb_port = config.couchdb.port if config.couchdb.protocol == 'http' else config.couchdb.ssl_port
    couchdb_url = "%s://%s:%s" % (config.couchdb.protocol, config.couchdb.host, couchdb_port)
    return couchdb_url

def get_auth_info():
    user, passwd = config.couchdb.user, config.couchdb.password
    if (all((user, passwd))):
        return (user, passwd)
    else:
        return None

def is_usable_workspace(ws_name):
    return not ws_name.startswith('_') and ws_name not in config.WS_BLACKLIST

def list_workspaces_as_user(cookies, credentials=None):
    all_dbs_url = get_couchdb_url() + '/_all_dbs'
    response = requests.get(all_dbs_url, verify=False, cookies=cookies, auth=credentials)
    if response.status_code != requests.codes.ok:
        raise Exception("Couldn't obtain workspaces list")

    def is_workspace_accessible_for_user(ws_name):
        return is_usable_workspace(ws_name) and\
               has_permissions_for(ws_name, cookies, credentials)

    workspaces = filter(is_workspace_accessible_for_user, response.json())
    return { 'workspaces': workspaces }

def server_has_access_to(ws_name):
    return has_permissions_for(ws_name, credentials=get_auth_info())

def get_workspace(workspace_name, cookies, credentials):
    workspace = _get_workspace_doc(workspace_name, cookies, credentials).json()
    ws_info_url = get_couchdb_url() + ('/%s' % (workspace_name))
    response = requests.get(ws_info_url, verify=False, cookies=cookies, auth=credentials)
    workspace['last_seq'] = response.json()['update_seq']
    return workspace

def _get_workspace_doc(workspace_name, cookies, credentials):
    # TODO: SANITIZE WORKSPACE NAME IF NECESSARY. POSSIBLE SECURITY BUG
    ws_url = get_couchdb_url() + ('/%s/%s' % (workspace_name, workspace_name))
    return requests.get(ws_url, verify=False, cookies=cookies, auth=credentials)

def has_permissions_for(workspace_name, cookies=None, credentials=None):
    response = _get_workspace_doc(workspace_name, cookies, credentials)
    # Even if the document doesn't exist, CouchDB will
    # respond 401 if it doesn't have access to it
    return (response.status_code != requests.codes.unauthorized)

def get_user_from_session(cookies=None, credentials=None):
    session_url = "%s/_session" % get_couchdb_url()
    res = requests.get(session_url, cookies=cookies, auth=credentials)
    if res.ok:
        user = res.json()['userCtx']['name']
    return user if user else ''

def push_reports():
    vmanager = ViewsManager()
    try:
        logger.debug(u'Pushing Reports DB into CouchDB')
        couchdb_server = CouchDBServer()
        workspace = couchdb_server.get_or_create_db('reports')
        vmanager.addView(config.REPORTS_VIEWS_DIR, workspace)
    except:
        import traceback
        logger.debug(traceback.format_exc())
        logger.warning("Reports database couldn't be uploaded. You need to be an admin to do it")

def upload_views(workspace):
    """ Upload views with couchdb behind of ViewsManager """
    vmanager = ViewsManager()
    try:
        vmanager.addViews(workspace)
    except:
        import traceback
        logger.debug(traceback.format_exc())
        logger.warning("Views documents couldn't be uploaded. You need to be an admin to do it")

def create_workspace(workspace):

    couch_server = CouchDBServer()
    couch_server.create_db(workspace.get('name'))

    ws = couch_server.get_workspace_handler(workspace.get('name'))
    upload_views(ws)

    try:
        response = ws.save_doc(workspace)
    except (RequestFailed, ResourceError):
        # create an error
        response = {'ok': False}

    success = response.get('ok', False)
    if not success:
        # if the document was not create, delete db
        couch_server.delete_db(workspace.get('name'))

    return success

def delete_workspace(ws_name):
    couch_server = CouchDBServer()
    try:
        couch_server.delete_db(ws_name)
    except:
        return False
    return True
