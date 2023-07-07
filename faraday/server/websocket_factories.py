"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import http.cookies
import json
import logging
from collections import defaultdict
from queue import Empty

# Related third party imports
import itsdangerous
import txaio
txaio.use_twisted()
# pylint:disable=import-outside-level
from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol
)
from sqlalchemy.orm.exc import NoResultFound
from twisted.internet import reactor

# Local application imports
from faraday.server.api.modules.websocket_auth import decode_agent_websocket_token
from faraday.server.events import changes_queue
from faraday.server.models import (
    db,
    Workspace,
    Agent,
    Executor,
    AgentExecution,
)
from faraday.server.utils.database import get_or_create
# pylint:enable=import-outside-level

logger = logging.getLogger(__name__)

connected_agents = {}


class BroadcastServerProtocol(WebSocketServerProtocol):

    def onConnect(self, request):
        protocol, headers = None, {}
        # see if there already is a cookie set ..
        logger.debug(f'Websocket request {request}')
        if 'cookie' in request.headers:
            try:
                cookie = http.cookies.SimpleCookie()
                cookie.load(str(request.headers['cookie']))
            except http.cookies.CookieError:
                pass
        return (protocol, headers)

    def onMessage(self, payload, is_binary):  # pylint:disable=arguments-renamed
        """
            We only support JOIN and LEAVE workspace messages.
            When authentication is implemented we need to verify
            that the user can join the selected workspace.
            When authentication is implemented we need to reply
            the client if the join failed.
        """
        from faraday.server.web import get_app  # pylint:disable=import-outside-toplevel
        if not is_binary:
            message = json.loads(payload)
            if message['action'] == 'JOIN_WORKSPACE':
                if 'workspace' not in message or 'token' not in message:
                    logger.warning(f'Invalid join workspace message: {message}')
                    self.sendClose()
                    return
                signer = itsdangerous.TimestampSigner(get_app().config['SECRET_KEY'],
                                                      salt="websocket")
                try:
                    workspace_id = signer.unsign(message['token'], max_age=60)
                except itsdangerous.BadData as e:
                    self.sendClose()
                    logger.warning(f'Invalid websocket token for workspace {message["workspace"]}')
                    logger.exception(e)
                else:
                    with get_app().app_context():
                        workspace = Workspace.query.get(int(workspace_id))
                    if workspace.name != message['workspace']:
                        logger.warning(f'Trying to join workspace {message["workspace"]} with token of '
                                       f'workspace {workspace.name}. Rejecting.')
                        self.sendClose()
                    else:
                        self.factory.join_workspace(
                            self, message['workspace'])
            if message['action'] == 'LEAVE_WORKSPACE':
                self.factory.leave_workspace(self, message['workspace'])
            if message['action'] == 'JOIN_AGENT':
                if 'token' not in message or 'executors' not in message:
                    logger.warning("Invalid agent join message")
                    self.sendClose(1000, reason="Invalid JOIN_AGENT message")
                    return False
                with get_app().app_context():
                    try:
                        agent = decode_agent_websocket_token(message['token'])
                        update_executors(agent, message['executors'])
                    except ValueError:
                        logger.warning('Invalid agent token!')
                        self.sendClose(1000, reason="Invalid agent token!")
                        return False
                    # factory will now send broadcast messages to the agent
                    return self.factory.join_agent(self, agent)
            if message['action'] == 'LEAVE_AGENT':
                with get_app().app_context():
                    (agent_id,) = (
                        k
                        for (k, v) in connected_agents.items()
                        if v == self
                    )
                    agent = Agent.query.get(agent_id)
                    assert agent is not None  # TODO the agent could be deleted here
                return self.factory.leave_agent(self, agent)
            if message['action'] == 'RUN_STATUS':
                with get_app().app_context():
                    if 'executor_name' not in message:
                        logger.warning(f'Missing executor_name param in message: {message}')
                        return True

                    (agent_id,) = (
                        k
                        for (k, v) in connected_agents.items()
                        if v == self
                    )
                    agent = Agent.query.get(agent_id)
                    assert agent is not None  # TODO the agent could be deleted here

                    execution_ids = message.get('execution_ids', None)
                    assert execution_ids is not None
                    for execution_id in execution_ids:
                        agent_execution = AgentExecution.query.filter(AgentExecution.id == execution_id).first()
                        if agent_execution:
                            agent_execution.successful = message.get('successful', None)
                            agent_execution.running = message.get('running', None)
                            agent_execution.message = message.get('message', '')
                            db.session.commit()
                        else:
                            logger.exception(
                                NoResultFound(f"No row was found for agent executor id {execution_id}"))

    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)
        self.factory.unregister_agent(self)

    def sendServerStatus(self, redirectUrl=None, redirectAfter=0):
        self.sendHtml('This is a websocket port.')


def update_executors(agent, executors):
    incoming_executor_names = set()
    for raw_executor in executors:
        if 'executor_name' not in raw_executor or 'args' not in raw_executor:
            continue
        executor, _ = get_or_create(
            db.session,
            Executor,
            **{
                'name': raw_executor['executor_name'],
                'agent': agent,
            }
        )

        executor.parameters_metadata = raw_executor['args']
        db.session.add(executor)
        db.session.commit()
        incoming_executor_names.add(raw_executor['executor_name'])

    current_executors = Executor.query.filter(Executor.agent == agent)
    for current_executor in current_executors:
        if current_executor.name not in incoming_executor_names:
            db.session.delete(current_executor)
            db.session.commit()

    return True


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
    protocol = BroadcastServerProtocol

    def __init__(self, url):
        WebSocketServerFactory.__init__(self, url)
        # this dict has a key for each channel
        # values are list of clients.
        self.workspace_clients = defaultdict(list)
        self.tick()

    def tick(self):
        """
            Uses changes_queue to broadcast messages to clients.
            broadcast method knows each client workspace.
        """
        try:
            msg = changes_queue.get_nowait()
            self.broadcast(json.dumps(msg))
        except Empty:
            pass
        reactor.callLater(0.5, self.tick)

    def join_workspace(self, client, workspace):
        logger.debug(f'Join workspace {workspace}')
        if client not in self.workspace_clients[workspace]:
            logger.debug(f"registered client {client.peer}")
            self.workspace_clients[workspace].append(client)

    def leave_workspace(self, client, workspace_name):
        logger.debug(f'Leave workspace {workspace_name}')
        self.workspace_clients[workspace_name].remove(client)

    @staticmethod
    def join_agent(agent_connection, agent):
        logger.info(f"Agent {agent.name} id {agent.id} joined!")
        connected_agents[agent.id] = agent_connection
        return True

    @staticmethod
    def leave_agent(agent_connection, agent):
        logger.info(f"Agent {agent.name} id {agent.id} left")
        connected_agents.pop(agent.id)
        return True

    def unregister(self, client_to_unregister):
        """
            Search for the client_to_unregister in all workspaces
        """
        for workspace_name, clients in self.workspace_clients.items():
            for client in clients:
                if client == client_to_unregister:
                    logger.debug(f"unregistered client from workspace {workspace_name}")
                    self.leave_workspace(client, workspace_name)
                    return

    @staticmethod
    def unregister_agent(protocol):
        for (key, value) in connected_agents.copy().items():
            if value == protocol:
                del connected_agents[key]
                logger.info(f"Agent {key} disconnected!")

    def broadcast(self, msg):
        if isinstance(msg, str):
            msg = msg.encode('utf-8')
        logger.debug(f"broadcasting prepared message '{msg}' ..")
        prepared_msg = json.loads(self.prepareMessage(msg).payload)
        if b'agent_id' not in msg:
            for client in self.workspace_clients[prepared_msg['workspace']]:
                reactor.callFromThread(client.sendPreparedMessage, self.prepareMessage(msg))
                logger.debug(f"prepared message sent to {client.peer}")

        if b'agent_id' in msg:
            agent_id = prepared_msg['agent_id']
            try:
                agent_connection = connected_agents[agent_id]
            except KeyError:
                # The agent is offline
                return
            reactor.callFromThread(agent_connection.sendPreparedMessage, self.prepareMessage(msg))
            logger.debug(f"prepared message sent to agent id: {agent_id}")
