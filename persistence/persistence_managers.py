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
from urlparse import urlparse
import traceback
from couchdbkit import Server, ChangesStream, Database
from couchdbkit.resource import ResourceNotFound

from utils.logs import getLogger
from managers.all import ViewsManager

#from persistence.change import change_factory

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class DBTYPE(object):
    COUCHDB = 1
    FS = 2


class ConnectorContainer(object):
    def __init__(self, name, connector, type):
        self._connector = connector
        self.type = type
        self._name = name

    def getType(self):
        return self.type

    def connector(self):
        if self._connector.__class__.__name__ == 'function':
            self._connector = self._connector(self._name)
        return self._connector


class DbManager(object):

    def __init__(self):
        self.load()

    def load(self): 
        self.couchmanager = CouchDbManager(CONF.getCouchURI())
        self.fsmanager = FileSystemManager()
        self.managers = {
                            DBTYPE.COUCHDB: self.couchmanager, 
                            DBTYPE.FS: self.fsmanager
                        }
        self.dbs = {}
        self._loadDbs()

    def getAvailableDBs(self):
        return  [typ for typ, manag in self.managers.items()\
                if manag.isAvailable()] 

    def _loadDbs(self):
        self.dbs = {}
        for dbname, connector in self.fsmanager.getDbs().items():
            self.dbs[dbname] = ConnectorContainer(dbname, connector, DBTYPE.FS)
        for dbname, connector in self.couchmanager.getDbs().items():
            self.dbs[dbname] = ConnectorContainer(dbname, connector, DBTYPE.COUCHDB)

    def _getManagerByType(self, dbtype):
        if dbtype == DBTYPE.COUCHDB:
            manager = self.couchmanager
        else:
            manager = self.fsmanager
        return manager

    def getConnector(self, name):
        # This returns a method that creates a connector
        # It's for lazy initalization in _loadDbs
        return self.dbs.get(name).connector()

    def connectorExists(self, name):
        return name in self.dbs.keys()

    def createDb(self, name, dbtype):
        if self.connectorExists(name):
            return False
        manager = self._getManagerByType(dbtype)
        self.addConnector(name, manager.createDb(name), dbtype)
        return self.getConnector(name)

    def addConnector(self, name, connector, dbtype):
        self.dbs[name] = ConnectorContainer(name, connector, dbtype)

    def getAllDbNames(self):
        self.refreshDbs()
        return self.dbs.keys()

    def refreshDbs(self):
        self.fsmanager.refreshDbs()
        self.couchmanager.refreshDbs()
        for dbname, connector in self.fsmanager.getDbs().items():
            if dbname not in self.dbs.keys():
                self.dbs[dbname] = ConnectorContainer(dbname, connector, DBTYPE.FS)
        for dbname, connector in self.couchmanager.getDbs().items():
            if dbname not in self.dbs.keys():
                self.dbs[dbname] = ConnectorContainer(dbname, connector, DBTYPE.COUCHDB)

    def removeDb(self, name):
        connector = self.getConnector(name)
        self._getManagerByType(connector.getType()).deleteDb(name)
        del self.dbs[name]
        return True

    def getDbType(self, dbname):
        return self.dbs.get(dbname).getType()

    def reloadConfig(self):
        self.load() 

class DbConnector(object):
    def __init__(self, type=None):
        self.changes_callback = None
        self.type = type

    def getType(self):
        return self.type

    def setChangesCallback(self, callback):
        self.changes_callback = callback

    def waitForDBChange(self):
        pass

    def forceUpdate(self):
        pass

    def saveDocument(self, document):
        raise NotImplementedError("DbConnector should not be used directly")

    def getDocument(self, documentId):
        raise NotImplementedError("DbConnector should not be used directly")

    def remove(self, documentId):
        raise NotImplementedError("DbConnector should not be used directly")

    def getDocsByFilter(self, parentId, type):
        raise NotImplementedError("DbConnector should not be used directly")

    def getChildren(self, document_id):
        raise NotImplementedError("DbConnector should not be used directly")


class FileSystemConnector(DbConnector):
    def __init__(self, base_path):
        super(FileSystemConnector, self).__init__(type=DBTYPE.FS)
        self.path = base_path
        self._available = True

    def saveDocument(self, dic):
        try:
            filepath = os.path.join(self.path, "%s.json" % dic.get("_id", ))
            getLogger(self).debug(
                "Saving document in local db %s" % self.path)
            with open(filepath, "w") as outfile:
                json.dump(dic, outfile, indent=2)
            return True
        except Exception:
            #log Exception?
            return False

    def getDocument(self, document_id):
        getLogger(self).debug(
            "Getting document %s for local db %s" % (document_id, self.path))
        path = os.path.join(self.path, "%s.json" % document_id)
        doc = None
        try:
            doc = open(path, "r")
            doc = json.loads(doc.read())
        except IOError:
            doc = None
        finally:
            return doc

    def remove(self, document_id):
        path = os.path.join(self.path, "%s.json" % document_id)
        if os.path.isfile(path):
            os.remove(path)

    def getDocsByFilter(self, parentId, type):
        result = []
        for name in os.listdir(self.path):
            path = os.path.join(self.path, name)
            document = open(path, "r")
            data = json.loads(document.read())
            if data.get("parent", None) == parentId:
                if data.get("type", None) == type or not type:
                    result.append(data)
        return result

    def getChildren(self, document_id):
        result = []
        for name in os.listdir(self.path):
            path = os.path.join(self.path, name)
            document = open(path, "r")
            data = json.loads(document.read())
            if data.get("parent", None) == document_id:
                result.append(data)
        return result


class CouchDbConnector(DbConnector):
    # This ratio represents (db size / num of docs)
    # to compact the database when the size is too high
    MAXIMUM_RATIO_SIZE = 10000
    # This value represents the number of maximum saves
    # before we try to compact the db
    MAXIMUM_SAVES = 1000

    def __init__(self, db, seq_num=0):
        super(CouchDbConnector, self).__init__(type=DBTYPE.COUCHDB)
        self.db = db
        self.saves_counter = 0
        #self.seq_num = seq_num
        self.mutex = threading.Lock()
        vmanager = ViewsManager()
        vmanager.addViews(self.db)
        self._docs = {}
        self._compactDatabase()
        self.seq_num = self.db.info()['update_seq']
        # self._tree = self._createTree(self.getDocs())

    def getDocs(self):
        if len(self._docs.keys()) == 0:
            # TODO: change this.
            # backwards compatibility. ugly, but needed
            self._docs["orphan"] = {}
            self._docs["orphan"]["children"] = []
            for doc in self.getAllDocs():
                self.addDoc(doc)
        return self._docs

    def addDoc(self, doc):
        id = doc["_id"]
        doc["children"] = []
        if self._docs.get(id, None):
            doc["children"] = self._docs[id]["children"]
        self._docs[id] = doc

        parent_id = doc.get("parent", None)
        # TODO: change this.
        # backwards compatibility. ugly, but needed
        if not parent_id or parent_id == "None":
            parent_id = "orphan"
        if parent_id in self._docs.keys():
            self._docs[parent_id]["children"].append(
                self._docs[doc["_id"]])

    def delDoc(self, doc_id):
        doc = self._docs[doc_id]
        parent_id = doc.get("parent", None)
        # TODO: change this.
        # backwards compatibility. ugly, but needed
        if not parent_id or parent_id == "None":
            parent_id == "orphan"
        if parent_id in self._docs.keys():
            self._docs[parent_id]["children"].remove(doc)
        del self._docs[doc_id]

    def _ratio(self):
        return self.db.info()['disk_size'] / self.db.info()['doc_count']

    #@trap_timeout
    def saveDocument(self, document):
        self.incrementSeqNumber()
        getLogger(self).debug(
            "Saving document in couch db %s" % self.db)
        res = self.db.save_doc(document, use_uuids=True, force_update=True)
        if res:
            self.saves_counter += 1
            self.addDoc(document)
        if self.saves_counter > self.MAXIMUM_SAVES:
            self._compactDatabase()
            self.saves_counter = 0
        return res

    def forceUpdate(self):
        doc = self.getDocument(self.db.dbname) 
        return self.db.save_doc(doc, use_uuids=True, force_update=True)

    #@trap_timeout
    def getDocument(self, document_id):
        # getLogger(self).debug(
        #     "Getting document %s for couch db %s" % (document_id, self.db))
        doc = self.getDocs().get(document_id, None)
        if not doc:
            if self.db.doc_exist(document_id):
                doc = self.db.get(document_id)
                self.addDoc(doc)
        return doc

    #@trap_timeout
    def remove(self, document_id):
        if self.db.doc_exist(document_id):
            self.incrementSeqNumber()
            self.db.delete_doc(document_id)
            self.delDoc(document_id)

    def getChildren(self, document_id):
        return self._docs[document_id]["children"]

    #@trap_timeout
    def getDocsByFilter(self, parentId, type):
        if not type:
            key = None
            if parentId:
                key = '%s' % parentId
            view = 'mapper/byparent'
            #print "query: view -> %s, key -> %s" % (view, key)
        else:
            key = ['%s' % parentId, '%s' % type]
            view = 'mapper/byparentandtype'

        values = [doc.get("value") for doc in self.db.view(view, key=key)]
        return values

    #@trap_timeout
    def getAllDocs(self):
        docs = [doc.get("value") for doc in self.db.view('utils/docs')]
        return docs

    def incrementSeqNumber(self):
        self.mutex.acquire()
        self.seq_num += 1
        self.mutex.release()

    def getSeqNumber(self):
        return self.seq_num

    def setSeqNumber(self, seq_num):
        self.seq_num = seq_num

    #@trap_timeout
    def waitForDBChange(self, since=0):
        getLogger(self).debug(
            "Watching for changes")
        while True:
            last_seq = max(self.getSeqNumber(), since)
            self.stream = ChangesStream(
                self.db,
                feed="continuous",
                since=last_seq,
                heartbeat=True)
            try:
                for change in self.stream:
                    if not self.changes_callback:
                        return
                    if not change.get('last_seq', None):
                        if change['seq'] > self.getSeqNumber():
                            self.setSeqNumber(change['seq'])
                            if not change['id'].startswith('_design'):
                                getLogger(self).debug(
                                    "Changes from another instance")
                                deleted = bool(change.get('deleted', False))
                                revision = change.get("changes")[-1].get('rev')
                                obj_id = change.get('id')
                                if not deleted:
                                    # update cache
                                    doc = self.db.get(obj_id)
                                    self.addDoc(doc)
                                self.changes_callback(obj_id, revision, deleted)
            except Exception as e:
                getLogger(self).info("Some exception happened while waiting for changes")
                getLogger(self).info("  The exception was: %s" % e)

    #@trap_timeout
    def _compactDatabase(self):
        self.db.compact()


class AbstractPersistenceManager(object):
    def __init__(self):
        self.dbs = {}
 
    def createDb(self, name):
        if not self.getDb(name):
            self.dbs[name] = self._create(name)
        return self.dbs[name]

    def _loadDbs(self):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def refreshDbs(self):
        self._loadDbs()

    def _create(self, name):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def deleteDb(self, name):
        if self.getDb(name):
            self._delete(name)
            del self.dbs[name]
            return True
        return False

    def _delete(self, name):
        raise NotImplementedError("AbstractPersistenceManager should not be used directly")

    def getDbNames(self):
        return self.dbs.keys()

    def getDbs(self):
        return self.dbs

    def getDb(self, name):
        return self.dbs.get(name, None)

    def isAvailable(self):
        return self._available


class FileSystemManager(AbstractPersistenceManager):
    """
    This is a file system manager for the workspace,
    it will load from the provided FS
    """
    def __init__(self, path=CONF.getPersistencePath()):
        super(FileSystemManager, self).__init__()
        getLogger(self).debug(
            "Initializing FileSystemManager for path [%s]" % path)
        self._path = path
        if not os.path.exists(self._path):
            os.mkdir(self._path)
        self._loadDbs()
        self._available = True

    def _create(self, name):
        wpath = os.path.expanduser("~/.faraday/persistence/%s" % name)
        if not os.path.exists(wpath):
            os.mkdir(wpath)
            return FileSystemConnector(wpath)
        return None

    def _delete(self, name):
        if os.path.exists(os.path.join(self._path, name)):
            shutil.rmtree(os.path.join(self._path, name))

    def _loadDbs(self):
        for name in os.listdir(CONF.getPersistencePath()):
            if os.path.isdir(os.path.join(CONF.getPersistencePath(), name)):
                if name not in self.dbs.keys():
                    self.dbs[name] = lambda x: self._loadDb(x)

    def _loadDb(self, name):
        self.dbs[name] = FileSystemConnector(os.path.join(self._path,
                                              name))
        return self.dbs[name]


class NoCouchDBError(Exception):
    pass


class NoConectionServer(object):
    """ Default to this server if no conectivity"""
    def create_db(*args):
        pass

    def all_dbs(*args, **kwargs):
        return []

    def get_db(*args):
        db_mock = mockito.mock(Database)
        mockito.when(db_mock).documents().thenReturn([])
        return db_mock

    def replicate(*args, **kwargs):
        pass

    def delete_db(*args):
        pass


class CouchDbManager(AbstractPersistenceManager):
    """
    This is a couchdb manager for the workspace,
    it will load from the couchdb databases
    """
    def __init__(self, uri):
        super(CouchDbManager, self).__init__()
        getLogger(self).debug(
            "Initializing CouchDBManager for url [%s]" % uri)
        self._lostConnection = False
        self.__uri = uri
        self.__serv = NoConectionServer()
        self._available = False
        try:
            if uri is not None:
                self.testCouchUrl(uri)
                url = urlparse(uri)
                getLogger(self).debug(
                    "Setting user,pass %s %s" % (url.username, url.password))
                self.__serv = Server(uri=uri)
                self.__serv.resource_class.credentials = (url.username, url.password)
                self._available = True
                self.pushReports()
                self._loadDbs()
        except:
            getLogger(self).warn("No route to couchdb server on: %s" % uri)
            getLogger(self).debug(traceback.format_exc())

    #@trap_timeout
    def _create(self, name):
        db = self.__serv.create_db(name.lower())
        return CouchDbConnector(db)

    #@trap_timeout
    def _delete(self, name):
        self.__serv.delete_db(name)

    #@trap_timeout
    def _loadDbs(self):
        conditions = lambda x: not x.startswith("_") and x != 'reports'
        for dbname in filter(conditions, self.__serv.all_dbs()):
            if dbname not in self.dbs.keys():
                getLogger(self).debug(
                    "Asking for dbname[%s], registering for lazy initialization" % dbname)
                self.dbs[dbname] = lambda x: self._loadDb(x)

    def _loadDb(self, dbname):
        db = self.__serv.get_db(dbname)
        seq = db.info()['update_seq']
        self.dbs[dbname] = CouchDbConnector(db, seq_num=seq) 
        return self.dbs[dbname]


    #@trap_timeout
    def pushReports(self):
        vmanager = ViewsManager()
        reports = os.path.join(os.getcwd(), "views", "reports")
        workspace = self.__serv.get_or_create_db("reports")
        vmanager.addView(reports, workspace)
        return self.__uri + "/reports/_design/reports/index.html"

    def lostConnectionResolv(self):
        self._lostConnection = True
        self.__dbs.clear()
        self.__serv = NoConectionServer()

    def reconnect(self):
        ret_val = False
        ur = self.__uri
        if CouchDbManager.testCouch(ur):
            self.__serv = Server(uri = ur)
            self.__dbs.clear()
            self._lostConnection = False
            ret_val = True

        return ret_val

    @staticmethod
    def testCouch(uri):
        if uri is not None:
            host, port = None, None
            try:
                import socket
                url = urlparse(uri)
                proto = url.scheme
                host = url.hostname
                port = url.port

                port = port if port else socket.getservbyname(proto)
                s = socket.socket()
                s.settimeout(1)
                s.connect((host, int(port)))
            except:
                return False
            #getLogger(CouchdbManager).info("Connecting Couch to: %s:%s" % (host, port))
            return True

    def testCouchUrl(self, uri):
        if uri is not None:
            url = urlparse(uri)
            proto = url.scheme
            host = url.hostname
            port = url.port
            self.test(host, int(port))

    def test(self, address, port):
        import socket
        s = socket.socket()
        s.settimeout(1)
        s.connect((address, port))

    #@trap_timeout
    def replicate(self, workspace, *targets_dbs, **kwargs):
        getLogger(self).debug("Targets to replicate %s" % str(targets_dbs))
        for target_db in targets_dbs:
            src_db_path = "/".join([self.__uri, workspace])
            dst_db_path = "/".join([target_db, workspace])
            try:
                getLogger(self).info("workspace: %s, src_db_path: %s, dst_db_path: %s, **kwargs: %s" % (workspace, src_db_path, dst_db_path, kwargs))
                self.__peerReplication(workspace, src_db_path, dst_db_path, **kwargs)
            except ResourceNotFound as e:
                raise e
            except Exception as e:
                getLogger(self).error(e)
                raise 

    def __peerReplication(self, workspace, src, dst, **kwargs):
        mutual = kwargs.get("mutual", True)
        continuous = kwargs.get("continuous", True)
        ct = kwargs.get("create_target", True)

        self.__serv.replicate(workspace, dst, mutual = mutual, continuous  = continuous, create_target = ct)
        if mutual:
            self.__serv.replicate(dst, src, continuous = continuous, **kwargs)
