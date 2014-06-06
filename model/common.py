'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
Contains base classes used to represent the application model
and some other common objects and functions used in the model
"""
import sys
import os
import traceback
import threading
import SimpleXMLRPCServer
import xmlrpclib
from utils.decorators import updateLocalMetadata, save, delete
import json
import model
from conflict import ConflictUpdate
from model.diff import ModelObjectDiff

try:
    import model.api as api
except AttributeError:
    import api
from utils.common import *

#----------- Metadata history for timeline support, prob. we should move this out model common

from time import time
import cPickle as pickle
from config.configuration import getInstanceConfiguration

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

        # api.devlog("Updating object (%s) metadata for user: (%s), utime = (%.4f), action=(%d), controller action = (%s)"
        #                     % (self, self.update_user, self.update_time, self.update_action, self.update_controller_action))

    def __getUpdateAction(self):
        """This private method grabs the stackframes in look for the controller
        call that generated the update"""

        l_strace = traceback.extract_stack(limit = 10)
        controller_funcallnames = [ x[2] for x in l_strace if "controller" in x[0] ]
        
        if controller_funcallnames:
            return "ModelControler." +  " ModelControler.".join(controller_funcallnames)
        return "No model controller call"
        
class PickleBackedDict(dict): 
    def __init__(self, path, filename = None):
        self.path = os.path.join(path, filename) if not filename is None else path
        self.lock = threading.Lock()
        if os.path.exists(self.path):
            with open(self.path, 'rb') as f:
                self.dict = pickle.load(f)

        else:
            self.dict = {}

    def cleanUp(self):
        with self.lock:
            if os.path.isfile(self.path): 
                os.remove(self.path)
            self.dict = {}
            # with open(self.path, 'wb', 0) as writer:
            #     self.dict = {}
            #     pickle.dump(self.dict, writer)


    def __setitem__(self, key, value):
        # When we set an item, we update the old dict
        try:
            with self.lock:
                with open(self.path, 'wb', 0) as writer:
                    self.dict.__setitem__(key, value)
                    pickle.dump(self.dict, writer)
        except Exception, e:
            raise e

    def __getitem__(self, key):
        return self.dict.__getitem__(key)

    def get(self, key, default = None):
        return self.dict.get(key, default)

    def __repr__(self):
        return self.dict.__repr__()

    def __str__(self):
        return self.dict.__str__()



class MetadataHistory(object):
    """Wrap object for the history of metadata objects, just a wrap for an
    object dict that persists to disc"""
    class_signature = "MetadataHistory"

    _history_dict = PickleBackedDict(path = getInstanceConfiguration().getPersistencePath(), 
                                              filename = "metadata.pickle" )
    
    def __init__(self, *args):
        self._history_dict = MetadataHistory._history_dict

    def getHistory(self, objId):
        """docstring for getHistory"""
        return self._history_dict.get(objId, [])

    def setHistory(self, objId, obj):
        
        self._history_dict[objId] =  obj
        
    def pushMetadataForId(self, objId, obj):
        """Adds the metadata in obj for id into the internal rep. """ 
        pass
        # print "Object ID is: ", objId, " with type ", type(objId)
        # hist = self.getHistory(objId)
        # hist.append(obj)
        # self.setHistory(objId, hist)

    def cleanUp(self):
        self._history_dict.cleanUp()


    def toDict(self):
        return self._history_dict
    def fromDict(self, dictt):
        self._history_dict.update(dictt)



        
#-------------------------------------------------------------------------------
class ModelObjectDictAdapter(object):
    def __init__(self):
        self.excepts = ["_id"]
        self.modified = []

        # Here I register the classes I need on the factory to create the objects:
        factory.register(model.hosts.Host)
        factory.register(model.hosts.Interface)
        factory.register(model.hosts.Service)
        factory.register(model.hosts.HostApplication)
        factory.register(model.common.ModelObjectVuln)
        factory.register(model.common.ModelObjectNote)
        factory.register(model.common.ModelObjectCred)
        factory.register(model.common.Metadata)
        factory.register(model.common.MetadataHistory)



    def toDict(self, obj): 
        obj_dict = obj.toDict().copy()
        normalized_dict = {}

        normalized_dict.update(self._normalizeKeys(obj_dict))

        return normalized_dict

    def _normalizeKeys(self, obj_dict):
        normalized_dict = {}
        for k, v in obj_dict.items():
            if k is not None and k.startswith('_') and not k in self.excepts: 
                k = k.replace('_', '', 1)
                self.modified.append(k)
            if isinstance(v, dict): v = self._normalizeKeys(v)
            normalized_dict[k] = v

        return normalized_dict

    def _denormalizeKeys(self, dictt):
        denormalized_dict = {}
        for k, v in dictt.items():
            if k in self.modified:
                k = "_" + k
            if isinstance(v, dict): v = self._denormalizeKeys(v)
            denormalized_dict[k] = v

        return denormalized_dict

    def fromDict(self, obj, dictt):
        dictt = self._denormalizeKeys(dictt)
        return obj.fromDict(dictt)


class ModelObject(object):
    """
    This is the base class for every object we need to represent in the
    system (like hosts, services, etc)
    It defines some generic methods to handle internal attributes that are
    dictionaries. It also has generic methods to deal with notes & vulns
    since every object could have them.
    """
    # this static attribute used with a factory
    class_signature = "ModelObject"
    #_complex_attribs = ["_metadata", "_metadataHistory", "_notes", "_vulns", "_creds"]
    _complex_attribs = ["_notes", "_vulns", "_creds"]

    def __init__(self):
        self._name          = ""
        self._id            = None
        self._parent        = None
        
        self.owner          = api.getLoggedUser()
        self._metadata      = Metadata(self.owner)
        self._metadataHistory = MetadataHistory()

        
        # this flag is used to determine if the object is an instance that is
        # inside the ModelController or is just a copy of an existing ModelObject
        # that can be used without worrying about changes affecting the real object
        self.is_copy       = False
        
        # indicates if object was owned somehow
        # we could use this property to put a different color on the GUI
        self._is_owned      = False

        # a custom description given by the user
        # this can be used to explain the purpose of the object
        self.description    = ""

        #IMPORTANT: this must be used in each object that inherits from this class
        # DO NOT REDEFINE THIS, JUST ADD ENTRIES IN ORDER NOT TO LOOSE INHERITED ATTRS
        # this attribute lists all values that can be shown in the gui, or
        # can be accessed from outside. This is done to do things more generic and
        # dynamic. The object that needs to use this should check if the element
        # in the attribute list is callable or not
        # To use this attributes list something like this should be done
        # >>> for attrDesc, attrName in m_object.publicattrs.iteritems():
        # >>>     attr_ref = m_object.__getattribute__(attrName)
        # >>>     if callable(attr_ref):
        # >>>         info = attr_ref()
        # >>>     else:
        # >>>         info = attr_ref
        # the dictionary key is the description of the attribute that is like a
        # display name to be used if needed to show in a GUI for example
        # and the value is the attribute name, that can be the name of an attribute,
        # a method or a property, that is why it needs to be checked with callable()

        self.publicattrs = {'Description':'description',
                            'Name':'getName','Owned':'isOwned',
                            #'Vulnerabilities' : 'vulnsCount',
                            #'Notes' : 'notesCount',
                            #'Creds' : 'credsCount'}
                            }

        self.publicattrsrefs = {'Description': '_description',
                            'Name': '_name','Owned': '_is_owned',
                            #'Vulnerabilities' : '_vulns',
                            #'Notes' :'_notes',
                            #'Creds' :'_creds'} 
                            }

        self._updatePublicAttributes()

        #TODO: I think notes and vulns should be a dict
        self._notes = {}
        self._vulns = {}
        self._creds = {}
        self.evidences = []

        self.updates = []

    def accept(self, visitor):
        visitor.visit(self) 

    def defaultValues(self):
        return [-1, 0, '', 'unknown', None, [], {}]

    def __getAttribute(self, key):
        """ Looks for the attribute beneth the public attribute dict """
        return self.publicattrsrefs.get(key)

    def propertyTieBreaker(self, key, prop1, prop2):
        """ Breakes the conflict between two properties. If either of them
        is a default value returns the true and only.
        If neither returns the default value.
        If conflicting returns a tuple with the values """ 
        if prop1 in self.defaultValues(): return prop2
        elif prop2 in self.defaultValues(): return prop1
        elif self.tieBreakable(key): return self.tieBreak(key, prop1, prop2)
        else: return (prop2, prop1)

    def tieBreakable(self, key): 
        return False

    def tieBreak(self, key, prop1, prop2):
        return None

    def addUpdate(self, newModelObject):
        conflict = False
        diff = ModelObjectDiff(self, newModelObject) 
        for k, v in diff.getPropertiesDiff().items():
            attribute = self.__getAttribute(k)
            prop_update = self.propertyTieBreaker(attribute, *v)
            if isinstance(prop_update, tuple):
                conflict = True
            else:
                setattr(self, attribute, prop_update) 
        if conflict:
            self.updates.append(ConflictUpdate(self, newModelObject))
        return conflict

    def getUpdates(self):
        return self.updates

    def updateResolved(self, update):
        self.updates.remove(update)

    
    # IMPORTANT: all delete methods are considered FULL delete
    # this means it will delete the reference from host and all
    # other objects containing them
    def _getValueByID(self, attrName, ID):
        """
        attribute passed as a parameter MUST BE a dictionary indexed with a
        string ID
        if id is found as a part of a key it returns the object
        it returns None otherwise
        """
        if ID:
            hash_id = get_hash([ID])
            ref = self.__getattribute__(attrName)
            # we are assuming the value is unique inside the object ID's
            for key in ref:
                #XXX: this way of checking the ids doesn't allow us to use a real hash as key
                # because we are checking if "id" is part of the key... not a good way  of
                # dealing with this...
                if hash_id == key or ID == key:
                    return ref[key]
            # if id (hash) was not found then we try with element names
            for element in ref.itervalues():
                #if id in element.name:
                if ID == element.name:
                    return element
        return None


    def _addValue(self, attrName, newValue, setparent = False, update = False):
        # attribute passed as a parameter MUST BE  the name
        # of an internal attribute which is a dictionary indexed
        # with a string ID
        valID = newValue.getID()
        ref = self.__getattribute__(attrName)
        if valID not in ref or update:
            ref[valID] =  newValue
            if setparent:
                newValue.setParent(self)
            return True
            #return not update
        return False

    
    def _updatePublicAttributes(self):
        # can be overriden if needed
        pass


    def setID(self, ID=None):
        if ID is None:
            self.updateID()
        else:
            self._id = ID
        return self._id
            
    def updateID(self):
        # MUST be overriden
        # if not overriden then name is the id
        self._id = get_hash([self._name])

    def getID(self):
        if self._id is None:
            self.updateID()
        return self._id

    id = property(getID, setID)
    
    def getMetadata(self):
        """Returns the current metadata of the object"""
        return self._metadata
    
    def getMetadataHistory(self):
        """Returns the current metadata of the object"""
        return self._metadataHistory

    def updateMetadata(self):
        """ We are only saving the previous state so the newst is not available"""
        self.getMetadata().update(self.owner)
        # self.getMetadataHistory().pushMetadataForId(self.getID(), self.getMetadata())
    
    def getHost(self):
        #recursive method to recover the Host root
        if self.class_signature == "Host":
            return self
        return self.getParent().getHost()

    def setName(self, name):
        self._name = name

    def getName(self):
        return self._name

    name = property(getName, setName)
    
    def setDescription(self, description):
        self._description = description

    def getDescription(self):
        return self._description
    
    description = property(getDescription, setDescription)
    
    def isOwned(self):
        return self._is_owned

    def setOwned(self, owned=True):
        self._is_owned = owned

    @save
    def setParent(self, parent):
        self._parent = parent

    def getParent(self):
        return self._parent
    
    parent = property(getParent, setParent)
    
    #TODO: this should be removed and we could use some class
    # based on dict to implement this


    def _delValue(self, attrName, valID):
        # attribute passed as a parameter MUST BE  the name
        # of an internal attribute which is a dictionary indexed
        # with a string ID
        api.devlog("(%s)._delValue(%s, %s)" % (self, attrName, valID))
        ref = self.__getattribute__(attrName)
        api.devlog("ref.keys() = %s" % ref.keys())
        if valID in ref:
            val = ref[valID]
            del ref[valID]
            val.delete()
            return True
        
        hash_id = get_hash([valID])
        if hash_id in ref:
            val = ref[hash_id]
            del ref[hash_id]
            val.delete()
            return True
        
        for element in ref.itervalues():
            if valID == element.name:
                val = ref[element.getID()]
                del ref[element.getID()]
                val.delete()
                return True
            
        # none of the ids were found         
        return False

    def _delAllValues(self, attrName):
        ref = self.__getattribute__(attrName)
        try:
            ref.clear()
            return True
        except Exception:
            return False

    @delete
    def delete(self):
        del self

    def _getAllValues(self, attrName, mode = 0):
        """
        attribute passed as a parameter MUST BE a dictionary indexed with a
        string ID
        return all values in the dictionary
        mode = 0 returns a list of objects
        mode = 1 returns a dictionary of objects with their id as key
        """
        ref = self.__getattribute__(attrName)
        if mode:
            return ref
        else:
            return sorted(ref.values())

    def _getAllIDs(self, attrName):
        ref = self.__getattribute__(attrName)
        return ref.keys()

    def _getValueCount(self, attrName):
        ref = self.__getattribute__(attrName)
        return len(ref)

    def __repr__(self):
        return "<ModelObject %s at 0x%x>" % (self.__class__.__name__, id(self))

    def __str__(self):
        return "<ModelObject %s ID = %s at 0x%x>" % (self.__class__.__name__, self._id, id(self))

    #notes
    @updateLocalMetadata
    def addNote(self, newNote, update=False, setparent=True):
        return self._addValue("_notes", newNote, setparent=setparent, update=update)

    def newNote(self, name, text):
        note = ModelObjectNote(name, text, self)
        self.addNote(note)
        
    @updateLocalMetadata
    def delNote(self, noteID):
        return self._delValue("_notes", noteID)

    def getNotes(self):
        return self._notes.values()

    def getNote(self, noteID):
        return self._getValueByID("_notes", noteID)

    def notesToDict(self):
        d = []
        for note in self._notes.values():
            d.append(note.toDictFull())
        return d
    def notesCount(self):
        return len(self._notes.values())
        
    #Vulnerability
    @updateLocalMetadata
    def addVuln(self, newVuln, update=False, setparent=True):
        return self._addValue("_vulns", newVuln, setparent=setparent, update=update)

    @updateLocalMetadata
    def delVuln(self, vulnID):
        return self._delValue("_vulns", vulnID)

    def getVulns(self):
        return self._vulns.values()

    def getVuln(self, vulnID):
        return self._getValueByID("_vulns", vulnID)

    def vulnsCount(self):
        return len(self._vulns.values())

    def vulnsToDict(self):
        d = []
        for vuln in self._vulns.values():
            d.append(vuln.toDictFull())
        return d

    #creds
    @updateLocalMetadata
    def addCred(self, newCred, update=False, setparent=True):
        return self._addValue("_creds", newCred, setparent=setparent, update=update)

    def newCred(self, username, password):
        cred = ModelObjectCred(username, password, self)
        self.addCred(cred)
        
    @updateLocalMetadata
    def delCred(self, credID):
        return self._delValue("_creds", credID)

    def getCreds(self):
        return self._creds.values()

    def getCred(self, credID):
        return self._getValueByID("_creds", credID)

    def credsToDict(self):
        d = []
        for cred in self._creds.values():
            d.append(cred.toDictFull())
        return d


    def credsCount(self):
        return len(self._creds.values())
    
    def __getClassname(self, val):
        supported = factory.listModelObjectTypes()
        return filter(lambda x: val.lower().replace('_', '')[:-1] in x.lower(), supported)[0]

    def _asdict(self):
        return self.toDictFull()

    def ancestors_path(self):
            if self.getParent() is None:
                return str(self.getID())
            return ".".join([self.getParent().ancestors_path()] + [str(self.getID())])

    def _toDict(self, full=False):
        d = {   
                "_id" : self.ancestors_path(),
                "obj_id": self.getID(),
                "name" : self.name,
                "owned" : str(self.isOwned()),
                "parent" : self.getParent().getID() if self.getParent() is not None else "None",
                "owner" : self.owner,
                "description" : self.description,
                "metadata" : self.getMetadata().__dict__,
                "type" : self.class_signature
            }
        if full:
            d["note"] = {}
            d["vulnerability"] = {}
            d["cred"] = {}
            for note in self.getNotes():
                d["note"][note.getID()] = note._toDict(full)
            for vuln in self.getVulns():
                d["vulnerability"][vuln.getID()] = vuln._toDict(full)
            for cred in self.getCreds():
                d["cred"][cred.getID()] = cred._toDict(full)
        return d

    def _fromDict(self, dict):
        
        self.id = dict["obj_id"]
        self.name = dict["name"]
        self._is_owned  = True if dict.get("owned", "").upper() == "TRUE" else False
        #parent_id = dict["parent"]
        self.owner = dict["owner"]
        self.description = dict["description"]
        self._metadata = Metadata("").fromDict(dict["metadata"])

        if dict.get("note"):
            for note in dict["note"].values():
                n = ModelObjectNote("")
                n._parent = self
                n._fromDict(note)
                self.addNote(n, setparent=False)

        if dict.get("vulnerability"):
            for vuln in dict["vulnerability"].values():
                v = ModelObjectVuln("")
                if vuln.get("type") == ModelObjectVulnWeb.class_signature:
                    v = ModelObjectVulnWeb("")
                v._parent = self
                v._fromDict(vuln)
                self.addVuln(v, setparent=False)

        if dict.get("vulnerabilityweb"):
            for vuln in dict["vulnerabilityweb"].values():
                v = ModelObjectVulnWeb("")
                v._parent = self
                v._fromDict(vuln)
                self.addVuln(v, setparent=False)

        if dict.get("cred"):
            for cred in dict["cred"].values():
                c = ModelObjectCred("")
                c._parent = self
                c._fromDict(cred)
                self.addCred(c, setparent=False)

#-------------------------------------------------------------------------------
#TODO: refactor this class to make it generic so this can be used also for plugins
# then create a subclass and inherit the generic factory
class ModelObjectFactory(object):
    """
    Factory to creat any ModelObject type
    """
    def __init__(self):
        self._registered_objects = dict()

    def register(self, model_object):
        """registers a class into the factory"""
        self._registered_objects[model_object.class_signature] = model_object

    def listModelObjectClasses(self):
        """returns a list of registered classes"""
        return self._registered_objects.values()

    def getModelObjectClass(self, name):
        """get the class for a particular object typename"""
        return self._registered_objects[name]

    def listModelObjectTypes(self):
        """returns an array with object typenames the factory is able to create"""
        names = self._registered_objects.keys()
        names.sort()
        return names

    def createModelObject(self, classname, object_name=None, **objargs):
        if classname in self._registered_objects:
            if object_name is not None:
                tmpObj = self._registered_objects[classname](object_name,**objargs)
                return tmpObj
            else:
                raise Exception("Object name parameter missing. Cannot create object class: %s" % classname)
        else:
            raise Exception("Object class %s not registered in factory. Cannot create object." % classname)

#-------------------------------------------------------------------------------
# global reference kind of a singleton
factory = ModelObjectFactory()

#-------------------------------------------------------------------------------

class CustomXMLRPCRequestHandler(SimpleXMLRPCServer.SimpleXMLRPCRequestHandler):

    def __init__(self, *args, **kwargs):
        SimpleXMLRPCServer.SimpleXMLRPCRequestHandler.__init__(self, *args, **kwargs)

    def handle(self):
        try:
            api.devlog("-" * 60)
            api.devlog("[XMLRPCHandler] - request = %s" % str(self.request))
            api.devlog("[XMLRPCHandler] - client_address = %s" % str(self.client_address))
            api.devlog("[XMLRPCHandler] - server = %s" % str(self.server))
            api.devlog("-" * 60)
            SimpleXMLRPCServer.SimpleXMLRPCRequestHandler.handle(self)
        except Exception:
            api.devlog("[XMLRPCHandler] - An error ocurred while handling a request\n%s" % traceback.format_exc())

    def do_POST(self):
        """
        Handles the HTTP POST request.
        Attempts to interpret all HTTP POST requests as XML-RPC calls,
        which are forwarded to the server's _dispatch method for handling.

        This is a copy of the original do_POST, but it sends information about
        the client calling the server to the marshaled dispatch. This info
        can be later passed to the server
        """

        # Check that the path is legal
        if not self.is_rpc_path_valid():
            self.report_404()
            return

        try:
            # Get arguments by reading body of request.
            # We read this in chunks to avoid straining
            # socket.read(); around the 10 or 15Mb mark, some platforms
            # begin to have problems (bug #792570).
            max_chunk_size = 10*1024*1024
            size_remaining = int(self.headers["content-length"])
            L = []
            while size_remaining:
                chunk_size = min(size_remaining, max_chunk_size)
                L.append(self.rfile.read(chunk_size))
                size_remaining -= len(L[-1])
            data = ''.join(L)

            # In previous versions of SimpleXMLRPCServer, _dispatch
            # could be overridden in this class, instead of in
            # SimpleXMLRPCDispatcher. To maintain backwards compatibility,
            # check to see if a subclass implements _dispatch and dispatch
            # using that method if present.
            response = self.server._marshaled_dispatch(
                    data, getattr(self, '_dispatch', None)
                )
        except Exception, e: # This should only happen if the module is buggy
            # internal error, report as HTTP server error
            self.send_response(500)

            # Send information about the exception if requested
            if hasattr(self.server, '_send_traceback_header') and \
                    self.server._send_traceback_header:
                self.send_header("X-exception", str(e))
                self.send_header("X-traceback", traceback.format_exc())

            self.end_headers()
        else:
            # got a valid XML RPC response
            self.send_response(200)
            self.send_header("Content-type", "text/xml")
            self.send_header("Content-length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

            # shut down the connection
            self.wfile.flush()
            self.connection.shutdown(1)
#-------------------------------------------------------------------------------
# custom XMLRPC server with stopping function
#TODO: check http://epydoc.sourceforge.net/stdlib/SimpleXMLRPCServer.SimpleXMLRPCServer-class.html
# see if there is a way to know the ip caller
# looks like the request handler can give us that info
# http://epydoc.sourceforge.net/stdlib/BaseHTTPServer.BaseHTTPRequestHandler-class.html#address_string
#

class XMLRPCServer(SimpleXMLRPCServer.SimpleXMLRPCServer, threading.Thread):
    """
    Stoppable XMLRPC Server with custom dispatch to send over complete traceback
    in case of exception.
    """
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self)
        SimpleXMLRPCServer.SimpleXMLRPCServer.__init__(self, requestHandler = CustomXMLRPCRequestHandler, allow_none = True, *args,**kwargs)
        self._stop = False
        # set timeout for handle_request. If we don't the server will hang
        self.timeout = 2

    def run(self):
        self.serve_forever()
        api.devlog("serve_forever ended")
        return

    # overloaded method to be able to stop server
    def serve_forever(self):
        while not self._stop:
            self.handle_request()
        api.devlog("server forever stopped by flag")

    def stop_server(self):
        api.devlog("server stopping...")
        self._stop = True

    # The default dispatcher does not send across the whole stack trace.
    # Only type and value are passed back. The client has no way of knowing
    # the exact place where error occurred in the server (short of some
    # other means such as server logging). This dispatcher sends the whole
    # stack trace.
    def _dispatch(self, method, params):
        """Dispatches the XML-RPC method.

        XML-RPC calls are forwarded to a registered function that
        matches the called XML-RPC method name. If no such function
        exists then the call is forwarded to the registered instance,
        if available.

        If the registered instance has a _dispatch method then that
        method will be called with the name of the XML-RPC method and
        its parameters as a tuple
        e.g. instance._dispatch('add',(2,3))

        If the registered instance does not have a _dispatch method
        then the instance will be searched to find a matching method
        and, if found, will be called.

        Methods beginning with an '_' are considered private and will
        not be called.
        """

        func = None
        try:
            # check to see if a matching function has been registered
            func = self.funcs[method]
        except KeyError:
            if self.instance is not None:
                # check for a _dispatch method
                if hasattr(self.instance, '_dispatch'):
                    return self.instance._dispatch(method, params)
                else:
                    # call instance method directly
                    try:
                        func = SimpleXMLRPCServer.resolve_dotted_attribute(
                            self.instance,
                            method,
                            self.allow_dotted_names
                            )
                    except AttributeError:
                        pass

        if func is not None:
            try:
                # since we are using a keyword xmlrpc proxy this is sending
                # the info comes in form of args and kwargs
                # so params has 2 items, the first being a list or tuple
                # and the second a dictionary
                if len(params) == 2 and  isinstance(params[1],dict) and\
                ( isinstance(params[0],list) or isinstance(params[0],tuple) ) :
                    return func(*params[0], **params[1])
                else:
                    # this is the default way in case a normal xmlrpclib.ServerProxy is used
                    return func(*params)
            except Exception:
                # extended functionality to let the client have the full traceback
                msg = traceback.format_exc()
                raise xmlrpclib.Fault(1, msg)
        else:
            raise Exception('method "%s" is not supported' % method)


    def _marshaled_dispatch(self, data, dispatch_method = None):
        """Dispatches an XML-RPC method from marshalled (XML) data.

        XML-RPC methods are dispatched from the marshalled (XML) data
        using the _dispatch method and the result is returned as
        marshalled data. For backwards compatibility, a dispatch
        function can be provided as an argument (see comment in
        SimpleXMLRPCRequestHandler.do_POST) but overriding the
        existing method through subclassing is the prefered means
        of changing method dispatch behavior.
        """

        try:
            params, method = xmlrpclib.loads(data)

            # generate response
            if dispatch_method is not None:
                response = dispatch_method(method, params)
            else:
                response = self._dispatch(method, params)
            # wrap response in a singleton tuple
            response = (response,)
            response = xmlrpclib.dumps(response, methodresponse=1,
                                       allow_none=self.allow_none, encoding=self.encoding)
        except Fault, fault:
            response = xmlrpclib.dumps(fault, allow_none=self.allow_none,
                                       encoding=self.encoding)
        except Exception:
            # report exception back to server
            exc_type, exc_value, exc_tb = sys.exc_info()
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(1, "%s:%s" % (exc_type, exc_value)),
                encoding=self.encoding, allow_none=self.allow_none,
                )

        return response

#-------------------------------------------------------------------------------

class XMLRPCKeywordProxy(object):
    """
    custom XMLRPC Server Proxy capable of receiving keyword arguments
    when calling remote methods
    """
    def __init__(self, *args, **kwargs):
        self._xmlrpc_server_proxy = xmlrpclib.ServerProxy(*args, **kwargs)
    def __getattr__(self, name):
        call_proxy = getattr(self._xmlrpc_server_proxy, name)
        def _call(*args, **kwargs):
            return call_proxy(args, kwargs)
        return _call



#-------------------------------------------------------------------------------
class ModelObjectNote(ModelObject):
    """
    Simple class to store notes about any object.
    id will be used to number notes (based on a counter on the object being commented)
    parent will be a reference to the object being commented.
    To assing new text this:
        >>> note.text = "foobar"
    to append text + or  += operators can be used (no need to use text property):
        >>> note += " hello world!"
    """
    class_signature = "Note"
    
    def __init__(self, name="", text="", parent=None):
        ModelObject.__init__(self)
        self.name = str(name)
        #self._parent = parent
        self._text = str(text)

    def updateID(self):
        self._id = get_hash([self.name, self._text])

    def _setText(self, text):
        # clear buffer then write new text
#        self._text.seek(0)
#        self._text.truncate()
#        self._text.write(text)
        self._text = str(text)

    def _getText(self):
#        return self._text.getvalue()
        return self._text

    text = property(_getText, _setText)

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, text=None):
        if name is not None:
            self.setName(name)
        if text is not None:
            self.text = text

    def __add__(self, text):
        # to be able to concat/append using +
        # self._text.write(text)
        self._text = self._text + str(text)
        return self

    def __radd__(self, text):
        return self.__add__(str(text))

    def __iadd__(self, text):
        return self.__add__(str(text))

    def __str__(self):
        return self.text

    def __repr__(self):
        return self.text

    def _toDict(self, full=False):
        note = super(ModelObjectNote, self)._toDict(full)
        note["text"] = self._text
        return note

    def _fromDict(self, dict):
        super(ModelObjectNote, self)._fromDict(dict)
        self._text = dict["text"]

    def fromDict(self, dict):
        self._id = dict["_id"]
        self._text = dict["text"]
        self.name = dict["name"]
        
        for note in dict["notes"]:
            n = ModelObjectNote("")
            self.setParent(self)
            n.fromDict(note)
            self.addNote(n)
    
#-------------------------------------------------------------------------------
class ModelObjectVuln(ModelObject):
    """
    Simple class to store vulnerability about any object.
    id will be used to number vulnerability (based on a counter on the object being commented)
    parent will be a reference to the object being commented.   
    """
    class_signature = "Vulnerability"
    
    def __init__(self, name="",desc="", ref=None, severity="", parent=None):
        """
        The parameters refs can be a single value or a list with values
        """
        ModelObject.__init__(self)
        self.name = name
        #self._parent = parent

        self._desc = desc
        
        self.refs = []
        
        if isinstance(ref, list):
            self.refs.extend(ref)
        elif ref is not None:
            self.refs.append(ref)

        # Severity Standarization 
        self.severity = self.standarize(severity)

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

    def updateID(self):
        self._id = get_hash([self.name, self._desc])
        
    def _setDesc(self, desc):
        self._desc = desc

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, desc=None, severity=None, refs=None):
        if name is not None:
            self.setName(name)
        if desc is not None:
            self.desc = desc
        if severity is not None:
            self.severity = self.standarize(severity)
        if refs is not None:
            self.refs = refs

    def _getDesc(self):
        #return self._desc.getvalue()
        return self._desc

    desc = property(_getDesc, _setDesc)

    def __str__(self):
        return "vuln id:%s - %s" % (self.id, self.name)

    def __repr__(self):
        return self.__str__()

    def _toDict(self, full=False):
        vuln = super(ModelObjectVuln, self)._toDict(full)
        vuln["desc"] = self._desc
        vuln["severity"] = self.severity
        vuln["refs"] = self.refs
        return vuln

    def _fromDict(self, dict):
        super(ModelObjectVuln, self)._fromDict(dict)
        self._desc = dict["desc"]
        self.severity = dict["severity"]
        self.refs = dict["refs"]

    def fromDict(self, dict):
        self._id = dict["_id"]
        self._desc = dict["desc"]
        self.name = dict["name"]
        self.severity = dict["severity"]

        for ref in dict["refs"]:
            self.refs.append(ref)
        
        self.severity = dict["severity"]
        

#-------------------------------------------------------------------------------

#-------------------------------------------------------------------------------
class ModelObjectVulnWeb(ModelObjectVuln):
    """
    Simple class to store vulnerability web about any object.
    This Vuln support path, hostname, request and response
    parent will be a reference to the ModelObjectVuln being commented.   
    """
    class_signature = "VulnerabilityWeb"
    
    def __init__(self, name="",desc="", website="", path="", ref=None, severity="", parent=None, request="", response="",
                method="",pname="", params="",query="",category=""):
        """
        The parameters ref can be a single value or a list with values
        """
        ModelObjectVuln.__init__(self, name,desc, ref, severity, parent)
        self.path = path
        self.website = website
        self.request = request
        self.response = response
        self.method = method
        self.pname = pname
        self.params = params
        self.query = query
        self.category = category
        
    def updateID(self):
        self._id = get_hash([self.name, self.website, self.path, self.desc ])

    @save
    @updateLocalMetadata
    def updateAttributes(self, name=None, desc=None, website=None, path=None, refs=None, severity=None, request=None,
                        response=None, method=None, pname=None, params=None, query=None, category=None):
        super(ModelObjectVulnWeb, self).updateAttributes(name, desc, severity, refs)
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
        
    def _toDict(self, full=False):
        vuln = super(ModelObjectVulnWeb, self)._toDict(full)
        vuln['website'] = self.website
        vuln['path'] = self.path
        vuln['request'] = self.request
        vuln['response'] = self.response
        vuln['method'] = self.method
        vuln['pname'] = self.pname
        vuln['params'] = self.params
        vuln['query'] = self.query
        vuln['category'] = self.category
        return vuln

    def _fromDict(self, dict):
        super(ModelObjectVulnWeb, self)._fromDict(dict)
        self.path = dict["path"]
        self.website = dict["website"]
        self.request = dict["request"]
        self.response = dict["response"]
        self.method = dict["method"]
        self.pname = dict["pname"]
        self.params = dict["params"]
        self.query = dict["query"]
        self.category = dict["category"]

    def fromDict(self, dict):
        
        ModelObjectVuln.fromDict(dict)
        
        self.path = dict["path"]
        self.website = dict["website"]
        self.request = dict["request"]
        self.response = dict["response"]
        self.method = dict["method"]
        self.pname = dict["pname"]
        self.params = dict["params"]
        self.query = dict["query"]
        self.category = dict["category"]
        
        return True


#-------------------------------------------------------------------------------
class ModelObjectCred(ModelObject):
    """
    Simple class to store credentials about any object.
    id will be used to number credentials (based on a counter on the object being commented)
    parent will be a reference to the object being commented.
    To assing new password this:
        >>> cred.password = "foobar"
    to append text + or  += operators can be used (no need to use password property):
        >>> cred += " hello world!"
    """
    class_signature = "Cred"
    
    def __init__(self, username="", password="", parent=None):
        ModelObject.__init__(self)
        #self._parent = parent
        self.username = str(username)
        self._parent = parent
        # using StringIO instead of common str because is more memory efficient
#        self._password = StringIO()
#        if password: self._password.write(password)
        self._password = str(password)
    
    def updateID(self):
        self._id = get_hash([self.username, self.password])

    def _setPassword(self, password):
        # clear buffer then write new password
#        self._password.seek(0)
#        self._password.truncate()
#        self._password.write(password)
        self._password = str(password)

    def _getPassword(self):
#        return self._password.getvalue()
        return self._password

    password = property(_getPassword, _setPassword)

    @save
    @updateLocalMetadata
    def updateAttributes(self, username=None, password=None):
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password

    def __add__(self, password):
        # to be able to concat/append using +
        # self._password.write(password)
        self._password = self._password + str(password)
        return self

    def __radd__(self, password):
        return self.__add__(str(password))

    def __iadd__(self, password):
        return self.__add__(str(password))

    def __str__(self):
        return self.password

    def __repr__(self):
        return self.password

    def _toDict(self, full=False):
        cred = super(ModelObjectCred, self)._toDict(full)
        cred["username"] = self.username
        cred["password"] = self._password
        return cred

    def _fromDict(self, dict):
        super(ModelObjectCred, self)._fromDict(dict)
        self._password = dict["password"]
        self.username = dict["username"]

    def fromDict(self, dict):
        self._id = dict["_id"]
        self._password = dict["password"]
        self.username = dict["username"]
        
        #for cred in dict["creds"]:
        #    n = ModelObjectCred("")
        #    self.setParent(self)
        #    n.fromDict(cred)
        #    self.addCred(n)

class TreeWordsTries(object):
    instance = None       
    END = '_end_'
    root = dict()
    FOUND = True

    def __init__(self):
        self.partial_match = False
        self.partial_match_dict = {}
        self.cur_idx = 0

    def addWord(self, word):
        current_dict = self.root
        for letter in word:
            current_dict = current_dict.setdefault(letter, {})

        current_dict = current_dict.setdefault(self.END, self.END)

    def getWordsInText(self, text):
        current_dict = self.root
        list_of_word = list()
        w = ''
        for letter in text:
            if letter in current_dict:
                current_dict = current_dict[letter]
                w += letter
            elif self.END in current_dict:
                list_of_word.append(w)
                current_dict = self.root
                w = ''
            else:
                current_dict = self.root
                w = ''

        if self.END in current_dict:
            list_of_word.append(w)

        return list_of_word


    def isInTries(self, word):
        current_dict = self.root

        if word is None:
            return False

        for letter in word:
            if letter in current_dict:
                current_dict = current_dict[letter]
            else:
                return not self.FOUND
        else:
            if self.END in current_dict:
                return self.FOUND
            else:
                return False

    def __new__(cls, *args, **kargs): 
        if cls.instance is None:
            cls.instance = object.__new__(cls, *args, **kargs)
        return cls.instance

    def removeWord(self, word):
        previous_dict = None
        current_dict = self.root
        last_letter = ''

        if not self.isInTries(word):
            return

        for letter in word: 
            if letter in current_dict:
                if not previous_dict:
                    previous_dict = current_dict
                    last_letter = letter
                if len(current_dict.keys()) != 1:
                    previous_dict = current_dict
                    last_letter = letter
                current_dict = current_dict[letter]
        else:
            if self.END in current_dict:
                previous_dict.pop(last_letter)

    def clear(self):
        self.root = dict()
        self.FOUND = True



#-------------------------------------------------------------------------------
# taken from http://code.activestate.com/recipes/576477-yet-another-signalslot-implementation-in-python/
# under MIT License
#TODO: decide if we are going to use this...
class Signal(object):
    """
    used to handle signals between several objects
    """
    def __init__(self):
        self.__slots = WeakValueDictionary()

    def __call__(self, *args, **kargs):
        for key in self.__slots:
            func, _ = key
            func(self.__slots[key], *args, **kargs)

    def connect(self, slot):
        key = (slot.im_func, id(slot.im_self))
        self.__slots[key] = slot.im_self

    def disconnect(self, slot):
        key = (slot.im_func, id(slot.im_self))
        if key in self.__slots:
            self.__slots.pop(key)

    def clear(self):
        self.__slots.clear()

#-------------------------------------------------------------------------------
