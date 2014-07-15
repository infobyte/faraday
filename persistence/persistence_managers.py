'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import json
import os
import shutil
import mockito
import threading
from couchdbkit import Server, ChangesStream, Database
from couchdbkit.resource import ResourceNotFound

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class DBTYPE(object):
    COUCHDB = 1
    FS = 2


class DbManager(object):

    def __init__(self):
        #self.couchmanager = CouchDbManager()
        #self.fsmanager = FileSystemManager()
        self.dbs = {}
        self._loadDbs()

    def _loadDbs(self):
        self.dbs.update(self.fsmanager.getDbs())
        self.dbs.update(self.couchmanager.getDbs())

    def _getManagerByType(self, dbtype):
        if dbtype == DBTYPE.COUCHDB:
            manager = self.couchmanager
        else:
            manager = self.fsmanager
        return manager

    def getConnector(self, name):
        return self.dbs.get(name, None)

    def createDb(self, name, dbtype):
        if self.getConnector(name, None):
            return False
        manager = self._getManagerByType(dbtype)
        self.dbs[name] = manager.createDb(name)
        return True

    def getAllDbNames(self):
        return self.dbs.keys()

    def removeDb(self, name, dbtype):
        if self.getConnector(name, None):
            self.managers[dbtype].removeDb(name)
            del self.dbs[name]
            return True
        return False


class DbConnector(object):
    def __init__(self):
        pass

    def saveDocument(self, document):
        raise NotImplementedError("DbConnector should not be used directly")

    def getDocument(self, documentId):
        raise NotImplementedError("DbConnector should not be used directly")

    def remove(self, documentId):
        raise NotImplementedError("DbConnector should not be used directly")

    def getDocsByFilter(self, parentId, type):
        raise NotImplementedError("DbConnector should not be used directly")


class FileSystemConnector(DbConnector):
    def __init__(self, base_path):
        self.path = base_path

    def saveDocument(self, dic):
        try:
            filepath = os.path.join(self._path, "%s.json" % dic.get("_id"))
            with open(filepath, "w") as outfile:
                json.dump(dic, outfile, indent=2)
            return True
        except Exception:
            #log Exception?
            return False

    def getDocument(self, document_id):
        path = os.path.join(self._path, "%s.json" % document_id)
        document = open(path, "r")
        return json.loads(document.read())

    def remove(self, document_id):
        path = os.path.join(self._path, "%s.json" % document_id)
        if os.path.isfile(path):
            os.remove(path)


class CouchDbConnector(DbConnector):
    def __init__(self, db):
        self.db = db

    def saveDocument(self, document):
        pass

    def getDocument(self, document_id):
        pass

    def remove(self, document_id):
        pass


class AbstractPersistenceManager(object):
    def __init__(self):
        pass

    def createDb(self, name):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def deleteDb(self, name):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def getDbNames(self):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def getDbs(self):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")


# class FileSystemManager(AbstractPersistenceManager):
#     """
#     This is a file system manager for the workspace,
#     it will load from the provided FS
#     """
#     def __init__(self, path=CONF.getPersistencePath()):
#         super(FileSystemManager, self).__init__()
#         #getLogger(self).debug(
#         #    "Initializing FileSystemManager for path [%s]" % path)
#         self._path = path
#         if not os.path.exists(self._path):
#             os.mkdir(self._path)

#     def createDb(self, name):
#         wpath = os.path.expanduser("~/.faraday/persistence/%s" % name)
#         os.mkdir(wpath)

#     def deleteDb(self, name):
#         shutil.rmtree(os.path.join(self._path))

#     def getDbNames(self):
#         workspaces = []
#         for name in os.listdir(CONF.getPersistencePath()):
#             if os.path.isdir(os.path.join(CONF.getPersistencePath(), name)):
#                 workspaces.append(name)
#         return workspaces

#     def getDbs(self):
#         res = {}
#         for db_name in self.getDbNames():
#             res[db_name] = FileSystemConnector(os.path.join(self._path,
#                                                             db_name))
#         return res


# class NoCouchDBError(Exception):
#     pass


# class NoConectionServer(object):
#     """ Default to this server if no conectivity"""
#     def create_db(*args):
#         pass

#     def all_dbs(*args, **kwargs):
#         return []

#     def get_db(*args):
#         db_mock = mockito.mock(Database)
#         mockito.when(db_mock).documents().thenReturn([])
#         return db_mock

#     def replicate(*args, **kwargs):
#         pass

#     def delete_db(*args):
#         pass


# class CouchDbManager(AbstractPersistenceManager):
#     """
#     This is a couchdb manager for the workspace,
#     it will load from the couchdb databases
#     """
#     def __init__(self, uri):
#         super(CouchDbManager, self).__init__()
#         #getLogger(self).debug(
#             "Initializing CouchDBManager for url [%s]" % uri)
#         self._lostConnection = False
#         self.__uri = uri
#         #self.__dbs = {}
#         self.__seq_nums = {}
#         self.__serv = NoConectionServer()
#         self.mutex = threading.Lock()
#         self._available = False

#         #setting the doc types to load from couch
#         # def get_types(subclasses):
#         #     if len(subclasses):
#         #         head = subclasses[0]
#         #         tail = []
#         #         if len(subclasses[1:]):
#         #             tail = subclasses[1:]
#         #         return get_types(head.__subclasses__()) + [head.class_signature] + get_types(tail)
#         #     return []
#         # self._model_object_types = get_types([ModelObject])
#         try:
#             if uri is not None:
#                 self.testCouchUrl(uri)
#                 url = urlparse(uri)
#                 #getLogger(self).debug("Setting user,pass %s %s" % (url.username, url.password))
#                 self.__serv = Server(uri=uri)
#                 #print dir(self.__serv)
#                 self.__serv.resource_class.credentials = (url.username, url.password)
#                 self._available = True
#         except:
#             #getLogger(self).warn("No route to couchdb server on: %s" % uri)
#             #getLogger(self).debug(traceback.format_exc())

#     def createDb(self, name):
#         raise NotImplementedError("AbstractPersistenceManager should not be used directly")

#     def deleteDb(self, name):
#         raise NotImplementedError("AbstractPersistenceManager should not be used directly")

#     def getDbNames(self):
#         raise NotImplementedError("AbstractPersistenceManager should not be used directly")

#     def getDbs(self):
#         raise NotImplementedError("AbstractPersistenceManager should not be used directly")

#     def isAvailable(self):
#         return self._available

#     def lostConnectionResolv(self): 
#         self._lostConnection = True
#         self.__dbs.clear()
#         self.__serv = NoConectionServer()

#     def reconnect(self):
#         ret_val = False
#         ur = self.__uri
#         if CouchdbManager.testCouch(ur):
#             self.__serv = Server(uri = ur)
#             self.__dbs.clear()
#             self._lostConnection = False
#             ret_val = True

#         return ret_val

#     @staticmethod
#     def testCouch(uri):
#         if uri is not None:
#             host, port = None, None
#             try:
#                 import socket
#                 url = urlparse(uri)
#                 proto = url.scheme
#                 host = url.hostname
#                 port = url.port

#                 port = port if port else socket.getservbyname(proto)
#                 s = socket.socket()
#                 s.settimeout(1)
#                 s.connect((host, int(port)))
#             except:
#                 return False
#             #getLogger(CouchdbManager).info("Connecting Couch to: %s:%s" % (host, port))
#             return True

#     def testCouchUrl(self, uri):
#         if uri is not None:
#             url = urlparse(uri)
#             proto = url.scheme
#             host = url.hostname
#             port = url.port
#             self.test(host, int(port))

#     def test(self, address, port):
#         import socket
#         s = socket.socket()
#         s.settimeout(1)
#         s.connect((address, port))


#     @trap_timeout
#     def getWorkspacesNames(self):
#         return filter(lambda x: not x.startswith("_"), self.__serv.all_dbs())

#     def workspaceExists(self, name):
#         return name in self.getWorkspacesNames()


#     @trap_timeout
#     def addWorkspace(self, aWorkspace):
#         self.__serv.create_db(aWorkspace.lower())
#         return self._getDb(aWorkspace)

#     @trap_timeout
#     def addDocument(self, aWorkspaceName, documentId, aDocument):
#         self._getDb(aWorkspaceName)
#         self.incrementSeqNumber(aWorkspaceName)
#         self._getDb(aWorkspaceName)[documentId] = aDocument

#     @trap_timeout
#     def saveDocument(self, aDocument):
#         self.incrementSeqNumber(self.db_name)
#         getLogger(self).debug("Saving document in remote workspace %s" % self.db_name)
#         return self._getDb(self.db_name).save_doc(aDocument, use_uuids=True, force_update=True)

#     def _getDb(self, aWorkspaceName):
#         if not self.__dbs.has_key(aWorkspaceName):
#             self.__getDb(aWorkspaceName)
#         return self.__dbs.get(aWorkspaceName, None)

#     @trap_timeout
#     def __getDb(self, aWorkspaceName): 
#         aWorkspaceName = aWorkspaceName.lower()
#         getLogger(self).debug("Getting workspace [%s]" % aWorkspaceName)
#         workspacedb = self.__dbs.get(aWorkspaceName, self.__serv.get_db(aWorkspaceName))
#         if not self.__dbs.has_key(aWorkspaceName): 
#             getLogger(self).debug("Asking couchdb for workspace [%s]" % aWorkspaceName)
#             self.__dbs[aWorkspaceName] = workspacedb
#             self.__seq_nums[aWorkspaceName] = workspacedb.info()['update_seq'] 


#         return workspacedb

#     @trap_timeout
#     def getDocument(self, documentId):
#         getLogger(self).debug("Getting document for workspace [%s]" % self.db_name)
#         try:
#             return self._getDb(self.db_name).get(documentId)
#         except ResourceNotFound:
#             return None

#     @trap_timeout
#     def getDeletedDocument(self, aWorkspaceName, documentId, documentRev):
#         return self._getDb(aWorkspaceName).get(documentId, rev=documentRev)

#     @trap_timeout
#     def checkDocument(self, aWorkspaceName, documentName):
#         return  self._getDb(aWorkspaceName).doc_exist(documentName)


#     @trap_timeout
#     def replicate(self, workspace, *targets_dbs, **kwargs):
#         getLogger(self).debug("Targets to replicate %s" % str(targets_dbs))
#         for target_db in targets_dbs:
#             src_db_path = "/".join([self.__uri, workspace])
#             dst_db_path = "/".join([target_db, workspace])
#             try:
#                 getLogger(self).info("workspace: %s, src_db_path: %s, dst_db_path: %s, **kwargs: %s" % (workspace, src_db_path, dst_db_path, kwargs))
#                 self.__peerReplication(workspace, src_db_path, dst_db_path, **kwargs)
#             except ResourceNotFound as e:
#                 raise e
#             except Exception as e:
#                 getLogger(self).error(e)
#                 raise 

#     def __peerReplication(self, workspace, src, dst, **kwargs):
#         mutual = kwargs.get("mutual", True)
#         continuous = kwargs.get("continuous", True)
#         ct = kwargs.get("create_target", True)

#         self.__serv.replicate(workspace, dst, mutual = mutual, continuous  = continuous, create_target = ct)
#         if mutual:
#             self.__serv.replicate(dst, src, continuous = continuous, **kwargs)


#     def getLastChangeSeq(self, workspaceName):
#         self.mutex.acquire()
#         seq = self.__seq_nums[workspaceName]
#         self.mutex.release()
#         return seq

#     def setLastChangeSeq(self, workspaceName, seq_num):
#         self.mutex.acquire()
#         self.__seq_nums[workspaceName] = seq_num
#         self.mutex.release()


#     @trap_timeout
#     def waitForDBChange(self, db_name, since = 0, timeout = 15000):
#         """ Be warned this will return after the database has a change, if
#         there was one before call it will return immediatly with the changes
#         done"""
#         changes = []
#         last_seq = max(self.getLastChangeSeq(db_name), since)
#         db = self._getDb(db_name)
#         with ChangesStream(db, feed="longpoll", since=last_seq, timeout=timeout) as stream:
#             for change in stream:
#                 if change['seq'] > self.getLastChangeSeq(db_name):
#                     self.setLastChangeSeq(db_name, change['seq'])
#                     if not change['id'].startswith('_design'):
#                         #fake doc type for deleted objects
#                         doc = {'type': 'unknown', '_deleted': 'False', '_rev':[0]}
#                         if not change.get('deleted'):
#                             doc = self.getDocument(db_name, change['id'])
#                         changes.append(change_factory.create(doc))
#         if len(changes):
#             getLogger(self).debug("Changes from another instance")
#         return changes

#     @trap_timeout
#     def delete_all_dbs(self):
#         for db in self.__serv.all_dbs():
#             self.__serv.delete_db(db)

#     @trap_timeout
#     def existWorkspace(self, name):
#         return name in self.__serv.all_dbs()

#     @trap_timeout
#     def workspaceDocumentsIterator(self, workspaceName): 
#         return filter(self.filterConditions, self._getDb(workspaceName).documents(include_docs=True))

#     def filterConditions(self, doc):
#         ret = True
#         ret = ret and not doc["id"].startswith("_")
#         ret = ret and doc['doc']["type"] in self._model_object_types

#         return ret

#     @trap_timeout
#     def removeWorkspace(self, workspace_name):
#         return self.__serv.delete_db(workspace_name)

#     @trap_timeout
#     def remove(self, doc_id):
#         self.incrementSeqNumber(self.db_name)
#         self.__dbs[self.db_name].delete_doc(doc_id)

#     @trap_timeout
#     def compactDatabase(self, aWorkspaceName):
#         self._getDb(aWorkspaceName).compact()

#     def pushReports(self):
#         vmanager = ViewsManager()
#         reports = os.path.join(os.getcwd(), "views", "reports")
#         workspace = self.__serv.get_or_create_db("reports") 
#         vmanager.addView(reports, workspace)
#         return self.__uri + "/reports/_design/reports/index.html"


#     def addViews(self, workspaceName):
#         vmanager = ViewsManager()
#         workspace = self._getDb(workspaceName)
#         for v in vmanager.getAvailableViews():
#             vmanager.addView(v, workspace)

#     def getViews(self, workspaceName):
#         vmanager = ViewsManager()
#         workspace = self._getDb(workspaceName)
#         return vmanager.getViews(workspace)

#     def syncWorkspaceViews(self, workspaceName):
#         vmanager = ViewsManager()
#         workspace = self._getDb(workspaceName) 
#         installed_views = vmanager.getViews(workspace)
#         for v in vmanager.getAvailableViews():
#             if v not in installed_views: 
#                 vmanager.addView(v, workspace)

#     def incrementSeqNumber(self, workspaceName):
#         self.mutex.acquire()
#         if not self.__seq_nums.has_key(workspaceName):
#             self.__seq_nums[workspaceName] = 0
#         self.__seq_nums[workspaceName] += 1 
#         self.mutex.release()