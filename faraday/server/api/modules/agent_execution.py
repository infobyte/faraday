import logging

from flask import Blueprint
from marshmallow import fields
from sqlalchemy import func

from faraday.server.api.base import ReadOnlyView, PaginatedMixin, AutoSchema, FilterMixin
from faraday.server.models import AgentExecution, db
from faraday.server.schemas import PrimaryKeyRelatedField

agent_execution_api = Blueprint('agent_execution_api', __name__)
logger = logging.getLogger(__name__)


class AgentExecutionSchema(AutoSchema):
    agent_name = fields.Method("get_agent_name", dump_only=True)
    tool = fields.Method("get_tool", dump_only=True)
    create_date = fields.DateTime(dump_only=True)
    type = fields.String(dump_only=True, default="Local Agent")
    running = fields.Boolean(dump_only=True)
    successful = fields.Boolean(dump_only=True)
    category = fields.Method("get_category", dump_only=True)
    parameters_data = fields.Raw(dump_only=True)
    triggered_by = fields.String(dump_only=True)
    executor = PrimaryKeyRelatedField('id', dump_only=True)

    class Meta:
        model = AgentExecution
        fields = (
            'agent_name', 'tool', 'create_date', 'type',
            'running', 'successful', 'category', 'parameters_data',
            'triggered_by', 'executor'
        )

    def get_agent_name(self, obj):
        return obj.executor.agent.name

    def get_tool(self, obj):
        return obj.executor.tool

    def get_category(self, obj):
        return obj.executor.category


class AgentExecutionView(PaginatedMixin, ReadOnlyView, FilterMixin):
    route_base = 'agent_executions'
    model_class = AgentExecution
    schema_class = AgentExecutionSchema
    order_field = AgentExecution.id.desc()

    def _filter(self, *args, **kwargs):
        """
        Groups AgentExecutions by run_uuid, returning only one representative row per group.

        Uses the earliest execution (minimum ID) in each run_uuid group as the representative row.
        This is safe because all executions with the same run_uuid share identical values for
        frontend-required fields (running, successful, parameters_data.)

        Filters out executions with NULL run_uuid to avoid grouping old undefined executions.
        """
        subquery = (
            db.session.query(func.min(AgentExecution.id))
            .filter(AgentExecution.run_uuid.isnot(None))
            .group_by(AgentExecution.run_uuid)
            .subquery()
        )
        kwargs["extra_alchemy_filters"] = (AgentExecution.id.in_(subquery))
        return super()._filter(*args, **kwargs)

    def _paginate(self, query, hard_limit=0):
        #  Same as _filter
        subquery = (
            db.session.query(AgentExecution.run_uuid, func.min(AgentExecution.id).label("min_id"))
            .filter(AgentExecution.run_uuid.isnot(None))
            .group_by(AgentExecution.run_uuid)
            .subquery()
        )

        query = query.join(subquery, AgentExecution.id == subquery.c.min_id)

        return super()._paginate(query, hard_limit)


AgentExecutionView.register(agent_execution_api)
