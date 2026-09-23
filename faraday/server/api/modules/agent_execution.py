import json
import logging

from flask import Blueprint, abort
from marshmallow import fields
from sqlalchemy import and_, func

from faraday.server.api.base import ReadOnlyView, PaginatedMixin, AutoSchema, FilterMixin, BulkDeleteMixin
from faraday.server.models import Agent, AgentExecution, Executor, Workspace, db
from faraday.server.schemas import PrimaryKeyRelatedField

agent_execution_api = Blueprint('agent_execution_api', __name__)
logger = logging.getLogger(__name__)


class AgentExecutionSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    agent_name = fields.Method("get_agent_name", dump_only=True)
    agent_id = fields.Method("get_agent_id", dump_only=True)
    tool = fields.Method("get_tool", dump_only=True)
    create_date = fields.DateTime(dump_only=True)
    type = fields.String(dump_only=True, default="Local Agent")
    running = fields.Boolean(dump_only=True)
    successful = fields.Boolean(dump_only=True)
    category = fields.Method("get_category", dump_only=True)
    parameters_data = fields.Raw(dump_only=True)  # includes command
    triggered_by = fields.String(dump_only=True)
    executor = PrimaryKeyRelatedField('id', dump_only=True)
    update_date = fields.DateTime(dump_only=True)

    class Meta:
        model = AgentExecution
        fields = (
            'id', 'agent_name', 'agent_id', 'tool', 'create_date', 'type',
            'running', 'successful', 'category', 'parameters_data',
            'triggered_by', 'executor', 'update_date'
        )

    def get_agent_name(self, obj):
        return obj.executor.agent.name

    def get_agent_id(self, obj):
        return obj.executor.agent.id

    def get_tool(self, obj):
        return obj.executor.tool

    def get_category(self, obj):
        return obj.executor.category


class AgentExecutionView(BulkDeleteMixin, PaginatedMixin, ReadOnlyView, FilterMixin):
    route_base = 'agent_executions'
    model_class = AgentExecution
    schema_class = AgentExecutionSchema
    order_field = AgentExecution.id.desc()

    def _translate_filters(self, filters):
        """
        Groups AgentExecutions by run_uuid, returning only one representative row per group.

        Uses the earliest execution (minimum ID) in each run_uuid group as the representative row.
        This is safe because all executions with the same run_uuid share identical values for
        frontend-required fields (running, successful, parameters_data.)

        Filters out executions with NULL run_uuid to avoid grouping old undefined executions.
        """
        try:
            raw = json.loads(filters) if isinstance(filters, str) else dict(filters or {})
        except (ValueError, TypeError):
            abort(400, 'Invalid filter JSON')
        if not isinstance(raw, dict):
            abort(400, 'Invalid filter JSON')

        top = raw.get('filters', [])
        standard = []
        custom_conditions = []

        for f in top:
            if not isinstance(f, dict):
                standard.append(f)
                continue
            name = f.get('name')
            op = str(f.get('op') or 'eq').lower()
            val = f.get('val', '')

            if name == 'name':
                if op == 'contains':
                    custom_conditions.append(
                        AgentExecution.executor.has(Executor.agent.has(Agent.name.ilike(f'%{val}%')))
                    )
                elif op in ('eq', '=='):
                    custom_conditions.append(
                        AgentExecution.executor.has(Executor.agent.has(Agent.name == val))
                    )
                elif op in ('ne', '!=', 'neq'):
                    custom_conditions.append(
                        ~AgentExecution.executor.has(Executor.agent.has(Agent.name == val))
                    )
                else:
                    standard.append(f)
            elif name == 'triggered_by' and op == 'contains':
                standard.append({"name": "triggered_by", "op": "ilike", "val": f"%{val}%"})
            elif name == 'workspaces':
                vals = val if isinstance(val, list) else [v.strip() for v in str(val).split(',') if v.strip()]
                ws_ids = db.session.query(Workspace.id).filter(Workspace.name.in_(vals))
                if op in ('is_one_of', 'in'):
                    custom_conditions.append(AgentExecution.workspace_id.in_(ws_ids))
                elif op in ('is_not_one_of', 'not_in', 'nin'):
                    custom_conditions.append(AgentExecution.workspace_id.notin_(ws_ids))
                else:
                    abort(400, f"Unsupported operator {op!r} for workspaces filter; use 'is_one_of' or 'is_not_one_of'")
            else:
                standard.append(f)

        subquery = (
            db.session.query(func.min(AgentExecution.id))
            .filter(AgentExecution.run_uuid.isnot(None))
            .group_by(AgentExecution.run_uuid)
            .subquery()
        )

        extra = and_(AgentExecution.id.in_(subquery), *custom_conditions)
        raw['filters'] = standard
        return json.dumps(raw), extra

    def _filter(self, filters, extra_alchemy_filters=None, *args, **kwargs):
        translated, extra = self._translate_filters(filters)
        if extra_alchemy_filters is not None:
            extra = and_(extra_alchemy_filters, extra)
        return super()._filter(translated, extra_alchemy_filters=extra, **kwargs)

    def _paginate(self, query, hard_limit=0):
        # TODO: Duplicated code. Fix.
        subquery = (
            db.session.query(AgentExecution.run_uuid, func.min(AgentExecution.id).label("min_id"))
            .filter(AgentExecution.run_uuid.isnot(None))
            .group_by(AgentExecution.run_uuid)
            .subquery()
        )

        query = query.join(subquery, AgentExecution.id == subquery.c.min_id)

        return super()._paginate(query, hard_limit)

    def _envelope_list(self, objects, pagination_metadata=None):
        return {
            'rows': objects,
            'count': pagination_metadata.total if pagination_metadata else len(objects)
        }


AgentExecutionView.register(agent_execution_api)
