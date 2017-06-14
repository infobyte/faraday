import json
import Cookie
from collections import defaultdict
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

    def onMessage(self, payload, is_binary):
        """
            We only support JOIN and LEAVE workspace messages.
            When authentication is implemented we need to verify
            that the user can join the selected workspace.
            When authentication is implemented we need to reply
            the client if the join failed.
        """
        if not is_binary:
            message = json.loads(payload)
            if message['action'] == 'JOIN_WORKSPACE':
                self.factory.join_workspace(self, message['workspace'])
            if message['action'] == 'LEAVE_WORKSPACE':
                self.factory.leave_workspace(self, message['workspace'])

    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)


class WorkspaceServerFactory(WebSocketServerFactory):
    """
        This factory uses the changes_queue to broadcast
        message via websockets.

        Any message put on that queue will be sent to clients.

        Clients subscribe to workspace channels.
        This factory will broadcast message to clients subscribed
        on workspace.

        The message in the queue must contain the workspace.
    """
    def __init__(self, url):
        WebSocketServerFactory.__init__(self, url)
        # this dict has a key for each channel
        # values are list of clients.
        self.workspace_clients = defaultdict(list)
        self.tick()

    def tick(self):
        """
            Uses changes_queue to broadcast messages to clients.
            broadcast method knowns each client workspace.
        """
        try:
            msg = changes_queue.get_nowait()
            self.broadcast(json.dumps(msg))
        except Empty:
            pass
        reactor.callLater(0.5, self.tick)

    def join_workspace(self, client, workspace):
        print('Join workspace {0}'.format(workspace))
        if client not in self.workspace_clients[workspace]:
            print("registered client {}".format(client.peer))
            self.workspace_clients[workspace].append(client)

    def leave_workspace(self, client, workspace_name):
        print('Leave workspace {0}'.format(workspace_name))
        self.workspace_clients[workspace_name].remove(client)

    def unregister(self, client_to_unregister):
        """
            Search for the client_to_unregister in all workspaces
        """
        for workspace_name, clients in self.workspace_clients.items():
            for client in clients:
                if client == client_to_unregister:
                    print("unregistered client from workspace {0}".format(workspace_name))
                    self.leave_workspace(client, workspace_name)
                    return

    def broadcast(self, msg):
        print("broadcasting prepared message '{}' ..".format(msg))
        prepared_msg = json.loads(self.prepareMessage(msg).payload)
        for client in self.workspace_clients[prepared_msg['workspace']]:
            reactor.callFromThread(client.sendPreparedMessage, self.prepareMessage(msg))
            print("prepared message sent to {}".format(client.peer))
