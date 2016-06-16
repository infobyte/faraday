# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

import couchdbkit
import restkit
import threading
import server.utils.logger

from couchdbkit import Server
from couchdbkit.exceptions import ResourceNotFound
from couchdbkit.resource import CouchdbResource
from couchdbkit.changes import ChangesStream
from server import config

logger = server.utils.logger.get_logger(__name__)

class CouchDBServer(object):
    WS_BLACKLIST = ['reports', 'cajval_nterno', 'h_i_srvv_10000', 'h_i_srvv_200_000']

    def __init__(self):
        self.__get_server_uri()
        self.__authenticate()
        self.__connect()

    def __get_server_uri(self):
        couchdb_port = config.couchdb.port if config.couchdb.protocol == 'http' else config.couchdb.ssl_port
        self.__couchdb_uri = "%s://%s:%s" % (config.couchdb.protocol, config.couchdb.host, couchdb_port)

    def __authenticate(self):
        user, passwd = config.couchdb.user, config.couchdb.password
        if (all((user, passwd))):
            auth = restkit.BasicAuth(user, passwd)
            self.__auth_resource = CouchdbResource(filters=[auth])
        else:
            self.__auth_resource = None

    def __connect(self):
        self.__server = Server(uri=self.__couchdb_uri, resource_instance=self.__auth_resource)

    def list_workspaces(self):
        def workspace_filter(ws_name):
            return not ws_name.startswith('_') and ws_name not in CouchDBServer.WS_BLACKLIST
        return filter(workspace_filter, self.__server.all_dbs())

    def get_workspace_handler(self, ws_name):
        return self.__server.get_db(ws_name)


class Workspace(object):
    def __init__(self, ws_name):
        self.__server = CouchDBServer()
        self.__ws_name = ws_name
        self.__get_workspace()

    def __get_workspace(self):
        self.__workspace = self.__server.get_workspace_handler(self.__ws_name)

    def get_last_seq(self):
        return self.__workspace.info().get('update_seq', 0) # 'update_seq' / 'committed_update_seq'

    def get_document(self, doc_id):
        return self.__workspace.get(doc_id)

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
        logger.debug('Starting changes monitor for workspace {} since {}'.format(self.__ws_name, last_seq))
        ws_stream = ChangesStream(self.__workspace, feed='continuous',
            since=last_seq, include_docs=True, heartbeat=True)
        self.__changes_monitor_thread = ChangesMonitorThread(ws_stream, changes_callback)
        self.__changes_monitor_thread.daemon = True
        self.__changes_monitor_thread.start()

class Change(object):
    def __init__(self, change_doc):
        self.change_doc = change_doc
        self.doc = change_doc.get('doc')
        self.revision = change_doc.get('changes')[-1].get('rev')
        self.doc_id = change_doc.get('id')
        self.seq = change_doc.get('seq')

        self.deleted = bool(change_doc.get('deleted', False))
        self.updated = (int(self.revision.split('-')[0]) > 1)
        self.added = (not self.deleted and not self.updated)
    
class ChangesMonitorThread(threading.Thread):
    def __init__(self, ws_stream, changes_callback):
        super(ChangesMonitorThread, self).__init__()
        self.__ws_stream = ws_stream
        self.__changes_callback = changes_callback

    def run(self):
        for change_doc in self.__ws_stream:
            try:
                self.__changes_callback(Change(change_doc))
            except Exception, e:
                import traceback
                logger.debug(traceback.format_exc())
                raise e

