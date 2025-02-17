import logging

from flask import Blueprint
from marshmallow import fields
from sqlalchemy import func

from faraday.server.api.base import ReadOnlyView, PaginatedMixin, AutoSchema
from faraday.server.models import AgentExecution, db
from faraday.server.schemas import PrimaryKeyRelatedField

agent_execution_api = Blueprint('agent_execution_api', __name__)
logger = logging.getLogger(__name__)


class AgentExecutionSchema(AutoSchema):
    running = fields.Boolean()
    successful = fields.Boolean()
    message = fields.String()
    parameters_data = fields.Raw()
    triggered_by = fields.String()
    executor = PrimaryKeyRelatedField('id', dump_only=True)
    command = PrimaryKeyRelatedField('id', dump_only=True, allow_none=True)
    run_id = fields.Integer()

    class Meta:
        model = AgentExecution
        fields = (
            'running', 'successful', 'message', 'parameters_data',
            'triggered_by', 'executor', 'command', 'run_id'
        )


class AgentExecutionView(PaginatedMixin, ReadOnlyView):
    route_base = 'agent_executions'
    model_class = AgentExecution
    schema_class = AgentExecutionSchema
    order_field = AgentExecution.id.desc()

    def _paginate(self, query, hard_limit=0):
        # Select only distinct run_id rows
        subquery = (
            db.session.query(AgentExecution.run_id, func.min(AgentExecution.id).label("min_id"))
            .group_by(AgentExecution.run_id)
            .subquery()
        )

        query = query.join(subquery, AgentExecution.id == subquery.c.min_id)

        return super()._paginate(query, hard_limit)


AgentExecutionView.register(agent_execution_api)
