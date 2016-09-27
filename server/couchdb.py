# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import sys, time, json
import couchdbkit
import restkit
import threading, thread
import server.utils.logger
import requests

from couchdbkit import Server
from couchdbkit.exceptions import ResourceNotFound
from couchdbkit.resource import CouchdbResource
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


class Workspace(object):
    def __init__(self, ws_name, couchdb_server_conn=None):
        self.__ws_name = ws_name
        self.__server = couchdb_server_conn or CouchDBServer()
        self.__changes_monitor_thread = None
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

    def __get_all_docs(self, limit, offset=0):
        return self.__workspace.all_docs(include_docs=True, limit=limit, skip=offset)

    def start_changes_monitor(self, changes_callback, last_seq=0):
        logger.debug(u'Starting changes monitor for workspace {} since {}'.format(self.__ws_name, last_seq))
        ws_stream = ChangesStream(self.__ws_name, feed='continuous',
            since=last_seq, include_docs='true', heartbeat='true')
        self.__changes_monitor_thread = ChangesMonitorThread(ws_stream, changes_callback)
        self.__changes_monitor_thread.daemon = True
        self.__changes_monitor_thread.start()

    def close(self):
        if self.__changes_monitor_thread:
            self.__changes_monitor_thread.stop()
            self.__changes_monitor_thread = None

    def save_doc(self, document):
        return self.__workspace.save_doc(document)

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

class ChangesStream(object):
    ALL_DBS = "__ALL_WORKSPACES__"

    def __init__(self, db, **params):
        self.__db = db
        self.__url = self.__build_url()
        self.__params = params
        self.__response = None
        self.__stop = False

    def __build_url(self):
        if self.__db == ChangesStream.ALL_DBS:
            return get_couchdb_url() + '/_db_updates'
        else:
            return get_couchdb_url() + ('/%s/_changes' % self.__db)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def __next__(self):
        return self

    def __iter__(self):
        while not self.__stop:
            try:
                # TODO: Connection timeout is too long.
                self.__response = requests.get(
                    self.__url, params=self.__params,
                    stream=True, auth=get_auth_info())

                for raw_line in self.__response.iter_lines():
                    if self.__stop:
                        break

                    line = self.__sanitize(raw_line)
                    if not line:
                        continue

                    change = self.__parse_change(line)
                    if not change:
                        continue

                    yield change

            except Exception, e:
                # On workspace deletion, requests will probably
                # fail to perform the request or the connection
                # will be closed. Check if this was intentional
                # by checking on the __stop flag.
                if self.__stop:
                    break

                import traceback
                logger.debug(traceback.format_exc())

                # Close everything but keep retrying
                self.stop()
                self.__stop = False

                logger.warning(u"Lost connection to CouchDB. Retrying in 3 seconds...")
                time.sleep(3)
                logger.info(u"Retrying...")

    def __sanitize(self, raw_line):
        if not isinstance(raw_line, basestring):
            return None

        line = raw_line.strip()

        # Ignore line cases
        if not line:
            return None
        if line in ('{"results":', '],'):
            return None

        # Modify line cases
        if line.startswith('"last_seq"'):
            line = '{' + line
        if line.endswith(","):
            line = line[:-1]

        return line

    def __parse_change(self, line):
        try:
            obj = json.loads(line)
            return obj
        except ValueError:
            return None

    def stop(self):
        self.__stop = True
        if self.__response is not None:
            self.__response.close()
            self.__response = None

class Change(object):
    REQUIRED_FIELDS = ('doc', 'changes', 'id', 'seq')

    @staticmethod
    def validate(change_doc):
        return all(map(lambda prop: prop in change_doc, Change.REQUIRED_FIELDS))

    def __init__(self, change_doc):
        self.change_doc = change_doc
        self.doc = change_doc.get('doc')
        self.revision = change_doc.get('changes')[-1].get('rev')
        self.doc_id = change_doc.get('id')
        self.seq = change_doc.get('seq')

        self.deleted = bool(change_doc.get('deleted', False))
        self.updated = (int(self.revision.split('-')[0]) > 1)
        self.added = (not self.deleted and not self.updated)


class DBChange(object):
    @staticmethod
    def validate(change_doc):
        return True

    def __init__(self, change_doc):
        self.change_doc = change_doc
        self.type = change_doc.get('type', None)
        self.deleted = (self.type == 'deleted')
        self.created = (self.type == 'created')
        self.db_name = change_doc.get('db_name', None)

class MonitorThread(threading.Thread):
    CHANGE_CLS = None

    def __init__(self, stream, changes_callback):
        super(MonitorThread, self).__init__()
        self.__stream = stream
        self.__changes_callback = changes_callback

    def run(self):
        for change_doc in self.__stream:
            try:
                if self.CHANGE_CLS.validate(change_doc):
                    self.__changes_callback(self.CHANGE_CLS(change_doc))
                else:
                    logger.debug(u'Ignoring change: {}'.format(change_doc))

            except Exception, e:
                import traceback
                logger.debug(traceback.format_exc())
                logger.warning(u"Error while processing change. Ignoring. Offending change: {}".format(change_doc))

                if change_doc.get('error', None):
                    if change_doc.get('error') == 'unauthorized':
                        logger.error(u"Unauthorized access to CouchDB. Make sure faraday-server's"\
                            " configuration file has CouchDB admin's credentials set")
                        thread.interrupt_main()

                    # TODO: A proper fix is needed here
                    elif change_doc.get('reason') == 'no_db_file':
                        self.__stream.stop()
                        break

    def stop(self):
        self.__stream.stop()

class ChangesMonitorThread(MonitorThread):
    CHANGE_CLS = Change

class DBsMonitorThread(MonitorThread):
    CHANGE_CLS = DBChange

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

def start_dbs_monitor(changes_callback):
    logger.debug(u'Starting global workspaces monitor')
    dbs_stream = ChangesStream(ChangesStream.ALL_DBS, feed='continuous', heartbeat='true')
    monitor_thread = DBsMonitorThread(dbs_stream, changes_callback)
    monitor_thread.daemon = True
    monitor_thread.start()
    return monitor_thread

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

