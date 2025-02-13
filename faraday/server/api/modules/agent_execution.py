import logging

from flask import Blueprint
from marshmallow import fields
from faraday.server.api.base import ReadOnlyView, PaginatedMixin, AutoSchema
from faraday.server.models import AgentExecution
from faraday.server.schemas import PrimaryKeyRelatedField

agent_execution_api = Blueprint('agent_execution_api', __name__)
logger = logging.getLogger(__name__)


class AgentExecutionSchema(AutoSchema):
    id = fields.Integer(dump_only=True, attribute='id')
    running = fields.Boolean()
    successful = fields.Boolean()
    message = fields.String()
    parameters_data = fields.Raw()
    triggered_by = fields.String()
    executor = PrimaryKeyRelatedField('id', dump_only=True)
    command = PrimaryKeyRelatedField('id', dump_only=True, allow_none=True)

    class Meta:
        model = AgentExecution
        fields = (
            'id', 'running', 'successful', 'message', 'parameters_data',
            'triggered_by', 'executor', 'command',
        )


class AgentExecutionView(PaginatedMixin, ReadOnlyView):
    route_base = 'agent_executions'
    model_class = AgentExecution
    schema_class = AgentExecutionSchema
    order_field = AgentExecution.id.desc()


AgentExecutionView.register(agent_execution_api)
