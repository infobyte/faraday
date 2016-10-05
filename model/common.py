'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import sys
import os
import traceback
import threading
import SimpleXMLRPCServer
import xmlrpclib
from utils.decorators import updateLocalMetadata
import json
import model
from conflict import ConflictUpdate
from model.diff import ModelObjectDiff, MergeSolver

try:
    import model.api as api
except AttributeError:
    import api
from utils.common import *

#----------- Metadata history for timeline support, prob. we should move this out model common

from time import time
import cPickle as pickle
from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

"""
Contains base classes used to represent the application model
and some other common objects and functions used in the model
"""


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

        l_strace = traceback.extract_stack(limit = 10)
        controller_funcallnames = [ x[2] for x in l_strace if "controller" in x[0] ]

        if controller_funcallnames:
            return "ModelControler." +  " ModelControler.".join(controller_funcallnames)
        return "No model controller call"


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

    def __init__(self, parent_id=None):
        self._name          = ""
        self._id = None
        self._parent_id = parent_id
        self._parent = None

        self.owner          = api.getLoggedUser()
        self._metadata      = Metadata(self.owner)

        # indicates if object was owned somehow
        # we could use this property to put a different color on the GUI
        self._is_owned      = False

        # a custom description given by the user
        # this can be used to explain the purpose of the object
        self.description    = ""

        self.publicattrs = {'Description':'description',
                            'Name':'getName','Owned':'isOwned'
                            }

        self.publicattrsrefs = {'Description': '_description',
                            'Name': '_name','Owned': '_is_owned'
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
        else: return (prop1, prop2)

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

            if (not isinstance(prop_update, tuple) or
                    CONF.getMergeStrategy()):
                # if there's a strategy set by the user, apply it
                if isinstance(prop_update, tuple):
                    prop_update = MergeSolver(
                        CONF.getMergeStrategy()
                        ).solve(prop_update[0], prop_update[1])

                setattr(self, attribute, prop_update)
            else:
                conflict = True
        if conflict:
            self.updates.append(ConflictUpdate(self, newModelObject))
        return conflict

    def needs_merge(self, new_obj):
        return ModelObjectDiff(self, new_obj).existDiff()

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
        raise NotImplementedError("This should be overwritten")

    def _prependParentId(self):
        if self._parent_id:
            self._id = '.'.join((self._parent_id, self.getID()))

    def getID(self):
        if self._id is None:
            self.updateID()
        return self._id

    id = property(getID, setID)

    def getMetadata(self):
        """Returns the current metadata of the object"""
        return self._metadata.__dict__

    def setMetadata(self, metadata):
        self._metadata = metadata

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

    def getOwner(self):
        return self.owner

    def setOwner(self, owner=None):
        self.owner = owner

    #@save
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

    #@delete
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
        self.addChild(newNote)
        return True

    def newNote(self, name, text):
        note = ModelObjectNote(name, text, self)
        self.addNote(note)

    @updateLocalMetadata
    def delNote(self, noteID):
        self.deleteChild(noteID)
        return True

    def getNotes(self):
        return self.getChildsByType(ModelObjectNote.__name__)

    def setNotes(self, notes):
        self._addChildsDict(notes)

    def getNote(self, noteID):
        return self.findChild(noteID)

    def notesCount(self):
        return len(self._notes.values())

    #Vulnerability
    @updateLocalMetadata
    def addVuln(self, newVuln, update=False, setparent=True):
        self.addChild(newVuln)
        return True

    @updateLocalMetadata
    def delVuln(self, vulnID):
        self.deleteChild(vulnID)
        return True

    def getVulns(self):
        return self.getChildsByType(ModelObjectVuln.__name__) + self.getChildsByType(ModelObjectVulnWeb.__name__)

    def setVulns(self, vulns):
        self._addChildsDict(vulns)

    def getVuln(self, vulnID):
        return self.findChild(vulnID)

    def vulnsCount(self):
        return len(self._vulns.values())

    def vulnsToDict(self):
        d = []
        for vuln in self._vulns.values():
            d.append(vuln.toDictFull())
        return d

    @updateLocalMetadata
    def delCred(self, credID):
        return self._delValue("_creds", credID)

    def getCreds(self):
        return self.getChildsByType(ModelObjectCred.__name__)

    def setCreds(self, creds):
        self._addChildsDict(creds)

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

    def _addChildsDict(self, dictt):
        [self.addChild(v) for k, v in dictt.items()]


class ModelComposite(ModelObject):
    """ Model Objects Composite Abstract Class """

    def __init__(self, parent_id=None):
        ModelObject.__init__(self, parent_id)
        self.childs = {}

    def addChild(self, model_object):
        model_object.setParent(self)
        self.childs[model_object.getID()] = model_object

    def getChilds(self):
        return self.childs

    def getChildsByType(self, signature):
        return [c for c in self.childs.values()
                    if c.__class__.__name__ == signature]

    def deleteChild(self, iid):
        del self.childs[iid]

    def findChild(self, iid):
        return self.childs.get(iid)

class ModelLeaf(ModelObject):
    def __init__(self, parent_id=None):
        ModelObject.__init__(self, parent_id)

    def getChildsByType(self, signature):
        return []

    def getChilds(self):
        return {}

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

    def generateID(self, classname, parent_id='', **objargs):
        # see how nicely formated that dictionary is
        # it's a building about to go down on an eathquake!
        # let's try not to make that an analogy about my code, ok? thank you :)
        appropiate_class = self._registered_objects[classname]
        class_to_args = {'Host': (objargs.get('name'),),
                         'Cred': (objargs.get('name'), objargs.get('password')),
                         'Note': (objargs.get('name'),
                                  objargs.get('text')),
                         'Service': (objargs.get('protocol'),
                                     objargs.get('ports')),
                         'Interface': (objargs.get('network_segment'),
                                       objargs.get('ipv4_address'),
                                       objargs.get('ipv6_address')),
                         'Vulnerability': (objargs.get('name'),
                                           objargs.get('desc')),
                         'VulnerabilityWeb': (objargs.get('name'),
                                              objargs.get('website'))
                         }
        try:
            id = appropiate_class.generateID(parent_id, *class_to_args[classname])
        except KeyError:
            raise Exception("You've provided an invalid classname")
        return id

    def createModelObject(self, classname, object_name, workspace_name=None, parent_id=None, **objargs):
        if not workspace_name:
            workspace_name = CONF.getLastWorkspace()
        if classname in self._registered_objects:
            if object_name is not None:
                objargs['name'] = object_name
                objargs['_id'] = -1 # they still don't have a server id
                objargs['id'] = self.generateID(classname, parent_id, **objargs)
                tmpObj = self._registered_objects[classname](objargs, workspace_name)
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
class ModelObjectNote(ModelComposite):
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

    def __init__(self, name="", text="", parent_id=None):
        ModelComposite.__init__(self, parent_id)
        self.name = str(name)
        self._text = str(text)

    def updateID(self):
        self._id = get_hash([self.name, self._text])
        self._prependParentId()

    def _setText(self, text):
        # clear buffer then write new text
#        self._text.seek(0)
#        self._text.truncate()
#        self._text.write(text)
        self._text = str(text)

    def _getText(self):
#        return self._text.getvalue()
        return self._text

    def getText(self):
#        return self._text.getvalue()
        return self._text

    def setText(self, text):
#        return self._text.getvalue()
        self._text = str(text)

    text = property(_getText, _setText)

    #@save
    @updateLocalMetadata
    def updateAttributes(self, name=None, text=None):
        if name is not None:
            self.setName(name)
        if text is not None:
            self.text = text

    def __str__(self):
        return "%s: %s" % (self.name, self.text)

    def __repr__(self):
        return "%s: %s" % (self.name, self.text)


class ModelObjectVuln(ModelComposite):
    class_signature = "Vulnerability"

    def __init__(self, name="", desc="", ref=None, severity="", resolution="",
                 confirmed=False, parent_id=None):
        """
        The parameters refs can be a single value or a list with values
        """
        ModelComposite.__init__(self, parent_id)
        self.name = name
        self._desc = desc
        self.data = ""
        self.confirmed = confirmed
        self.refs = []

        if isinstance(ref, list):
            self.refs.extend(ref)
        elif ref is not None:
            self.refs.append(ref)

        # Severity Standarization
        self.severity = self.standarize(severity)
        self.resolution = resolution

    def _updatePublicAttributes(self):

        self.publicattrs['Name'] = 'getName'
        self.publicattrs['Description'] = 'getDescription'
        self.publicattrs['Data'] = "getData"
        self.publicattrs['Severity'] = 'getSeverity'
        self.publicattrs['Refs'] = 'getRefs'
        self.publicattrs['Resolution'] = 'getResolution'

        self.publicattrsrefs['Name'] = 'name'
        self.publicattrsrefs['Description'] = '_desc'
        self.publicattrsrefs['Data'] = "data"
        self.publicattrsrefs['Severity'] = 'severity'
        self.publicattrsrefs['Refs'] = 'refs'
        self.publicattrsrefs['Resolution'] = 'resolution'

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
        self._prependParentId()

    def tieBreakable(self, key):
        '''
        If the confirmed property has a conflict, there's two possible reasons:
            confirmed is false, and the new value is true => returns true
            confirmed is true, and the new value is false => returns true
        '''
        if key == "confirmed":
            return True
        return False

    def tieBreak(self, key, prop1, prop2):
        if key == "confirmed":
            return True
        return (prop1, prop2)

    def _setDesc(self, desc):
        self._desc = desc

    #@save
    @updateLocalMetadata
    def updateAttributes(self, name=None, desc=None, data=None,
                         severity=None, resolution=None, refs=None):
        if name is not None:
            self.setName(name)
        if desc is not None:
            self.setDescription(desc)
        if data is not None:
            self.setData(data)
        if resolution is not None:
            self.setResolution(resolution)
        if severity is not None:
            self.severity = self.standarize(severity)
        if refs is not None:
            self.refs = refs

    def _getDesc(self):
        return self._desc

    desc = property(_getDesc, _setDesc)

    def setDesc(self, desc):
        self._desc = desc

    def getDesc(self):
        return self._desc

    def getDescription(self):
        return self.getDesc()

    def setDescription(self, desc):
        self.setDesc(desc)

    def setResolution(self, resolution):
        self.resolution = resolution

    def getResolution(self):
        return self.resolution

    def getSeverity(self):
        return self.severity

    def setSeverity(self, severity):
        self.severity = self.standarize(severity)

    def getRefs(self):
        return self.refs

    def setRefs(self, refs):
        if isinstance(refs, list):
            self.refs.extend(refs)
        elif ref is not None:
            self.refs.append(refs)

    def setData(self, data):
        self.data = data

    def getData(self):
        return self.data

    def setConfirmed(self, confirmed):
        self.confirmed = confirmed

    def getConfirmed(self):
        return self.confirmed

    def __str__(self):
        return "vuln id:%s - %s" % (self.id, self.name)

    def __repr__(self):
        return self.__str__()


class ModelObjectVulnWeb(ModelObjectVuln):
    """
    Simple class to store vulnerability web about any object.
    This Vuln support path, hostname, request and response
    parent will be a reference to the ModelObjectVuln being commented.
    """
    class_signature = "VulnerabilityWeb"

    def __init__(self, name="", desc="", website="", path="", ref=None,
                 severity="", resolution="", request="", response="",
                 method="", pname="", params="", query="", category="",
                 confirmed=False, parent_id=None):
        """
        The parameters ref can be a single value or a list with values
        """
        ModelObjectVuln.__init__(
            self, name, desc, ref, severity, resolution, confirmed,
            parent_id)
        self.path = path
        self.website = website
        self.request = request
        self.response = response
        self.method = method
        self.pname = pname
        self.params = params
        self.query = query
        self.category = category

    def _updatePublicAttributes(self):

        self.publicattrs['Name'] = 'getName'
        self.publicattrs['Desc'] = 'getDescription'
        self.publicattrs['Data'] = 'getData'
        self.publicattrs['Severity'] = 'getSeverity'
        self.publicattrs['Refs'] = 'getRefs'
        self.publicattrs['Path'] = 'getPath'
        self.publicattrs['Website'] = 'getWebsite'
        self.publicattrs['Request'] = 'getRequest'
        self.publicattrs['Response'] = 'getResponse'
        self.publicattrs['Method'] = 'getMethod'
        self.publicattrs['Pname'] = 'getPname'
        self.publicattrs['Params'] = 'getParams'
        self.publicattrs['Query'] = 'getQuery'
        self.publicattrs['Category'] = 'getCategory'

        self.publicattrsrefs['Name'] = 'name'
        self.publicattrsrefs['Desc'] = '_desc'
        self.publicattrsrefs['Data'] = 'data'
        self.publicattrsrefs['Severity'] = 'severity'
        self.publicattrsrefs['Refs'] = 'refs'
        self.publicattrsrefs['Path'] = 'path'
        self.publicattrsrefs['Website'] = 'website'
        self.publicattrsrefs['Request'] = 'request'
        self.publicattrsrefs['Response'] = 'response'
        self.publicattrsrefs['Method'] = 'method'
        self.publicattrsrefs['Pname'] = 'pname'
        self.publicattrsrefs['Params'] = 'params'
        self.publicattrsrefs['Query'] = 'query'
        self.publicattrsrefs['Category'] = 'category'

    def updateID(self):
        self._id = get_hash([self.name, self.website, self.path, self.desc ])
        self._prependParentId()

    def getPath(self):
        return self.path

    def setPath(self, path):
        self.path = path

    def getWebsite(self):
        return self.website

    def setWebsite(self, website):
        self.website = website

    def getRequest(self):
        return self.request

    def setRequest(self, request):
        self.request = request

    def getResponse(self):
        return self.response

    def setResponse(self, response):
        self.response = response

    def getMethod(self):
        return self.method

    def setMethod(self, method):
        self.method = method

    def getPname(self):
        return self.pname

    def setPname(self, pname):
        self.pname = pname

    def getParams(self):
        return self.params

    def setParams(self, params):
        self.params = params

    def getQuery(self):
        return self.query

    def setQuery(self, query):
        self.query = query

    def getCategory(self):
        return self.category

    def setCategory(self, category):
        self.category = category

    #@save
    @updateLocalMetadata
    def updateAttributes(self, name=None, desc=None, data=None, website=None, path=None, refs=None,
                        severity=None, resolution=None, request=None,response=None, method=None,
                        pname=None, params=None, query=None, category=None):
        super(ModelObjectVulnWeb, self).updateAttributes(name, desc, data, severity, resolution, refs)
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


#-------------------------------------------------------------------------------
class ModelObjectCred(ModelLeaf):
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

    def __init__(self, username="", password="", parent_id=None):
        ModelLeaf.__init__(self, parent_id)
        self._username = str(username)
        self._password = str(password)

    def updateID(self):
        self._id = get_hash([self._username, self._password])
        self._prependParentId()

    def setPassword(self, password):
        self._password = str(password)

    def getPassword(self):
        return self._password

    def getUsername(self):
        return self._username

    def setUsername(self, username):
        self._username = str(username)

    password = property(getPassword, setPassword)

    username = property(getUsername, setUsername)

    #@save
    @updateLocalMetadata
    def updateAttributes(self, username=None, password=None):
        if username is not None:
            self.setUsername(username)
        if password is not None:
            self.setPassword(password)
