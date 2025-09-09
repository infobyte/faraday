"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""

# Standard library imports
import logging
import json

# Related third party imports
import itsdangerous
from flask import current_app, request
from flask_socketio import Namespace

# Local imports
from faraday.server.api.modules.websocket_auth import decode_agent_websocket_token
from faraday.server.models import Workspace, db, Executor, Agent, AgentExecution
from faraday.server.utils.database import get_or_create

logger = logging.getLogger(__name__)


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
        if raw_executor.get("category"):
            category = raw_executor["category"]
            executor.category = category
        if raw_executor.get("tool"):
            executor.tool = raw_executor["tool"]
        db.session.add(executor)
        db.session.commit()
        incoming_executor_names.add(raw_executor['executor_name'])

    current_executors = Executor.query.filter(Executor.agent == agent)
    for current_executor in current_executors:
        if current_executor.name not in incoming_executor_names:
            db.session.delete(current_executor)
            db.session.commit()

    return True


def remove_sid():
    try:
        agents = Agent.query.filter(Agent.sid!=None).all()  # noqa E711
    except Exception as error:
        logger.warning("Could not update agents table. %s", error)
        return
    logger.debug(f"Found {len(agents)} agents connected")
    for agent in agents:
        agent.sid = None
    db.session.commit()


class DispatcherNamespace(Namespace):
    def on_connect(self):
        self.send("Connected to faraday websocket")

    def on_disconnect(self):
        agent = Agent.query.filter(Agent.sid == request.sid).first()
        if not agent:
            logger.warning("An agent disconnected but id could not be found. SID %s", request.sid)
            return

        # Mark ongoing executions as failed due to disconnection
        db.session.query(AgentExecution).filter(
            AgentExecution.executor_id.in_(
                db.session.query(Executor.id).filter(Executor.agent_id == agent.id)
            ),
            AgentExecution.running.is_(True)
        ).update(
            {
                "running": False,
                "successful": False,
                "message": "Execution terminated due to agent disconnection."
            },
            synchronize_session=False
        )

        agent.sid = None
        db.session.commit()
        logger.info("Disconnecting agent %s with id %s", agent.name, agent.id)

    def on_run_status(self, data):
        logger.info(data)
        data = json.loads(data)
        execution_ids = data.get("execution_ids", [])
        if not execution_ids:
            logger.error("No execution IDs provided")
            return

        # Prepare values, keeping None if keys are missing
        update_values = {
            "running": data.get("running"),
            "successful": data.get("successful"),
            "message": data.get("message"),
        }

        # Remove keys that are None to avoid updating them
        update_values = {k: v for k, v in update_values.items() if v is not None}

        if not update_values:
            logger.warning("No valid fields to update for execution IDs: %s", execution_ids)
            return

        # Update AgentExecution in bulk
        db.session.query(AgentExecution).filter(AgentExecution.id.in_(execution_ids)).update(
            update_values, synchronize_session=False
        )
        db.session.commit()

    def on_join_agent(self, message):
        if 'token' not in message or 'executors' not in message:
            logger.warning("Invalid agent join message")
            self.emit("disconnect", {"reason": "Invalid join agent message"})
            return
        with current_app.app_context():
            try:
                agent = decode_agent_websocket_token(message['token'])
                agent.sid = request.sid
                db.session.commit()
                update_executors(agent, message['executors'])
                logger.info("Agent joined correctly")
                self.send("Agent joined correctly to dispatcher namespace")
            except ValueError:
                logger.warning('Invalid agent token!')
                self.emit("disconnect", {"reason": "Invalid agent token!"})
                return

    def on_leave_agent(self):
        self.disconnect(request.sid, namespace='/dispatcher')

    def on_join_workspace(self, message):
        if 'workspace' not in message or 'token' not in message:
            logger.warning(f'Invalid join workspace message: {message["action"]}')
            self.emit("disconnect")
            return
        signer = itsdangerous.TimestampSigner(current_app.config['SECRET_KEY'], salt="websocket")
        try:
            workspace_id = signer.unsign(message['token'], max_age=60)
        except itsdangerous.BadData as e:
            self.emit("disconnect")
            logger.warning(f"Invalid websocket token for workspace {message['workspace']}")
            logger.exception(e)
        else:
            with current_app.app_context():
                workspace = Workspace.query.get(int(workspace_id))
            if workspace.name != message['workspace']:
                logger.warning(f"Trying to join workspace {message['workspace']} "
                               f"with token of workspace {workspace.name}. "
                               f"Rejecting.")
                self.emit("disconnect")
