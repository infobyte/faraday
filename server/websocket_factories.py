import json
import Cookie
from Queue import Queue, Empty

from twisted.internet import reactor
# from twisted.python import log

from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol
)

changes_queue = Queue()


class BroadcastServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        protocol, headers = None, {}
        # see if there already is a cookie set ..
        print request
        if 'cookie' in request.headers:
            print 'cookie'
            print (str(request.headers['cookie']))
            print 'cookie'
            try:
                cookie = Cookie.SimpleCookie()
                cookie.load(str(request.headers['cookie']))
            except Cookie.CookieError:
                pass
        return (protocol, headers)

    def onOpen(self):
        self.factory.register(self)

    def onMessage(self, payload, isBinary):
        if not isBinary:
            msg = "{} from {}".format(payload.decode('utf8'), self.peer)
            self.factory.broadcast(msg)

    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)


class WorkspaceServerFactory(WebSocketServerFactory):

    def __init__(self, url):
        WebSocketServerFactory.__init__(self, url)
        self.workspace_clients = []
        self.tickcount = 0
        self.tick()

    def tick(self):
        try:
            msg = changes_queue.get_nowait()
            self.broadcast(json.dumps(msg))
        except Empty:
            pass
        reactor.callLater(0.5, self.tick)

    def register(self, client):
        print 'register'
        print client
        print 'register'

        if client not in self.workspace_clients:
            print("registered client {}".format(client.peer))
            self.workspace_clients.append(client)

    def unregister(self, client):
        if client in self.workspace_clients:
            print("unregistered client {}".format(client.peer))
            self.workspace_clients.remove(client)

    def broadcast(self, msg):
        print("broadcasting prepared message '{}' ..".format(msg))
        preparedMsg = self.prepareMessage(msg)
        for client in self.workspace_clients:
            reactor.callFromThread(client.sendPreparedMessage, preparedMsg)
            print("prepared message sent to {}".format(client.peer))
