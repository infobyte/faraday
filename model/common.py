'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import sys
import traceback
import threading
import logging
import xmlrpclib
import SimpleXMLRPCServer

try:
    import model.api as api
except AttributeError:
    import api

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()
logger = logging.getLogger(__name__)


# -------------------------------------------------------------------------------
# TODO: refactor this class to make it generic so this can be used also for plugins
#  then create a subclass and inherit the generic factory
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
        """Given a classname, parent_id and necessary objargs, return the ID
        of the object.

        Necesary objargs vary according to the object:
        Host --> name
        Cred --> Name, password
        Note --> Name, text
        Service --> Protocol, ports
        Interface --> Network segments, ipv4_address, ipv6_address
        Vuln --> name, desc
        VulnWeb --> name, website
        """

        # see how nicely formated that dictionary is
        # it's a building about to go down on an eathquake!
        # let's try not to make that an analogy about my code, ok? thank you :)
        # appropiate_class = self._registered_objects[classname]
        # class_to_args = {'Host': (objargs.get('name'),),
        #                  'Cred': (objargs.get('name'), objargs.get('password')),
        #                  'Note': (objargs.get('name'),
        #                           objargs.get('text')),
        #                  'Service': (objargs.get('protocol'),
        #                              objargs.get('ports')),
        #                  'Interface': (objargs.get('network_segment'),
        #                                objargs.get('ipv4_address'),
        #                                objargs.get('ipv6_address')),
        #                  'Vulnerability': (objargs.get('name'),
        #                                    objargs.get('desc')),
        #                  'VulnerabilityWeb': (objargs.get('name'),
        #                                       objargs.get('website'))
        #                  }
        # try:
        #     id = appropiate_class.generateID(parent_id, *class_to_args[classname])
        # except KeyError:
        #     raise Exception("You've provided an invalid classname")
        # return id

    def createModelObject(self, classname, object_name, workspace_name=None, parent_id=None, **objargs):
        """Given a registered classname, create an object of name object_name and
        with the properties found on objargs. ID will be generated for you.

        If workspace_name is None, it will be inferred from the CONF module.
        parent_id should only be None if classname is 'Host' or maybe 'Note' or 'Credential'.
        """
        if not workspace_name:
            workspace_name = CONF.getLastWorkspace()
            logger.warn('No workspace selected. Using last workspace {0}'.format(workspace_name))
        if classname in self._registered_objects:
            if object_name is not None:
                objargs['name'] = object_name
                objargs['_id'] = -1  # they still don't have a server id
                objargs['id'] = -1 # we'll generate it after making sure the objects are okey
                tmpObj = self._registered_objects[classname](objargs, workspace_name)
                return tmpObj
            else:
                raise Exception("Object name parameter missing. Cannot create object class: %s" % classname)
        else:
            raise Exception("Object class %s not registered in factory. Cannot create object." % classname)

# -------------------------------------------------------------------------------
# global reference kind of a singleton
factory = ModelObjectFactory()

# -------------------------------------------------------------------------------

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
        except Exception, e:  # This should only happen if the module is buggy
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
# -------------------------------------------------------------------------------
# custom XMLRPC server with stopping function
# TODO: check http://epydoc.sourceforge.net/stdlib/SimpleXMLRPCServer.SimpleXMLRPCServer-class.html
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
        SimpleXMLRPCServer.SimpleXMLRPCServer.__init__(self,
                                                       requestHandler=CustomXMLRPCRequestHandler,
                                                       allow_none=True, *args, **kwargs)
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
                if len(params) == 2 and isinstance(params[1], dict) and\
                        (isinstance(params[0], list) or isinstance(params[-1], tuple)):
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

    def _marshaled_dispatch(self, data, dispatch_method=None):
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
        except Exception:
            # report exception back to server
            exc_type, exc_value, exc_tb = sys.exc_info()
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(1, "%s:%s" % (exc_type, exc_value)),
                encoding=self.encoding, allow_none=self.allow_none,
                )

        return response

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
