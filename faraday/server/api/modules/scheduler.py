# Standard library imports
import dateutil
import json
import logging

# Related third party imports
from croniter import croniter
from flask import (
    Blueprint,
    abort,
    jsonify,
)
from flask_classful import route
from marshmallow import (
    ValidationError,
    fields,
    pre_dump,
    post_load,
    validate,
)

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    FilterMixin,
    PaginatedMixin,
    ReadWriteView,
    get_workspace
)
from faraday.server.api.modules.workspaces import WorkspaceSchema
from faraday.server.models import (
    SchedulerGeneric,
    db,
)
from faraday.server.schemas import (
    MetadataSchema,
    PrimaryKeyRelatedField,
    SelfNestedField,
)

logger = logging.getLogger(__name__)

schedule_api = Blueprint('schedule_api', __name__)

SCHEDULES_LIMIT = 2


def check_timezone(tz: str):
    if not dateutil.tz.gettz(tz):
        raise ValidationError("Invalid timezone")


def check_crontab(value):
    # The regex above only checks the shape; croniter validates field ranges
    # (e.g. minute 60, hour 24, step 0) that would otherwise raise at run time.
    if not croniter.is_valid(value):
        raise ValidationError('Invalid format, Please use basic crontab format, Example: 10 * 10 * *')


class SchedulerSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    description = fields.String(required=True)
    crontab = fields.String(required=True,
                            metadata={"example": "10 * 10 * *"},
                            validate=[validate.Regexp(
                                r"^(((([1-5]?\d(-([1-5]?\d))?|\*)(\/(\d+))?),?)+)\ (((((2[0-3]|1?\d)(-(2["
                                r"0-3]|1?\d))?|\*)(\/(\d+))?),?)+)\ (((((3[01]|[12]?\d)(-(3[01]|[12]?\d))?|\*)(\/("
                                r"\d+))?),?)+)\ (((((1[0-2]|\d)(-(1[0-2]|\d))?|\*)(\/(\d+))?),?)+)\ (((([0-6](-(["
                                r"0-6]))?|\*)(\/(\d+))?),?)+)$",
                                0,
                                error='Invalid format, Please use basic crontab format, Example: 10 * 10 * *'),
                                check_crontab])
    timezone = fields.String(required=True, validate=check_timezone)
    active = fields.Boolean(default=False)
    next_run = fields.String(dump_only=True)
    parameters = fields.Method(
        deserialize='load_parameters',
        serialize='send_parameters'
    )
    owner = PrimaryKeyRelatedField('username', dump_only=True, attribute='owner')
    metadata = SelfNestedField(MetadataSchema())
    workspaces_names = fields.List(fields.String, required=True)
    workspaces = fields.List(fields.Pluck(WorkspaceSchema, 'name'))
    ignore_info = fields.Boolean(required=False, default=False)
    resolve_hostname = fields.Boolean(required=False, default=True)
    vuln_tag = fields.List(fields.String, required=False)
    service_tag = fields.List(fields.String, required=False)
    host_tag = fields.List(fields.String, required=False)
    min_severity = fields.String(required=False, allow_none=True, validate=validate.OneOf(SchedulerGeneric.SEVERITIES))
    max_severity = fields.String(required=False, allow_none=True, validate=validate.OneOf(SchedulerGeneric.SEVERITIES))

    # Not required: the polymorphic identity of each subclass already sets it
    type = fields.String(required=False, validate=validate.OneOf(SchedulerGeneric.SCHEDULER_TYPES))

    # Conditionally required fields
    executor_id = fields.Int(required=False, allow_none=True)
    cloud_agent_id = fields.Int(required=False, allow_none=True)

    class Meta:
        fields = (
            'id',
            'cloud_agent_id',
            'executor_id',
            'description',
            'crontab',
            'timezone',
            'active',
            'owner',
            'metadata',
            'workspaces_names',
            'workspaces',
            'ignore_info',
            'resolve_hostname',
            'vuln_tag',
            'service_tag',
            'host_tag',
            'parameters',
            'type',
            'next_run',
            'min_severity',
            'max_severity',
        )

    @staticmethod
    def load_parameters(value):
        return json.loads(value)

    @staticmethod
    def send_parameters(value):
        return value.parameters

    @post_load
    def process_tags(self, data, **kwargs):
        if "workspaces_names" in data:
            workspaces = [get_workspace(workspace_name=workspace_name) for workspace_name
                          in data.pop("workspaces_names")]
            data['workspaces'] = workspaces
        if "vuln_tag" in data:
            data['vuln_tag'] = ",".join(data['vuln_tag'])
        if "host_tag" in data:
            data['host_tag'] = ",".join(data['host_tag'])
        if "service_tag" in data:
            data['service_tag'] = ",".join(data['service_tag'])
        return data

    @pre_dump
    def pre_dump_agent_data(self, data, **kwargs):
        if data.vuln_tag:
            data.vuln_tag = data.vuln_tag.split(',')
        if data.host_tag:
            data.host_tag = data.host_tag.split(',')
        if data.service_tag:
            data.service_tag = data.service_tag.split(',')
        return data

    @staticmethod
    def get_agent(obj):
        raise NotImplementedError("Subclasses must implement this method")


class SchedulerView(PaginatedMixin, ReadWriteView, FilterMixin):
    schema_class = SchedulerSchema
    model_class = SchedulerGeneric
    order_field = SchedulerGeneric.id.asc()

    def _envelope_list(self, objects, pagination_metadata=None):
        """Sends pagination data and rows"""

        schedule_list = []
        objects = objects if objects is not None else []
        for schedule in objects:
            schedule_list.append({
                'id': schedule['id'],
                'key': schedule['id'],
                'value': schedule
            })
        return {
            'rows': schedule_list,
            'total_rows': pagination_metadata.total if pagination_metadata else len(schedule_list),
        }

    def _check_schedules_limit(self):
        schedules_in_use = db.session.query(SchedulerGeneric).count()
        if schedules_in_use >= SCHEDULES_LIMIT:
            message = "Agent schedules limit reached. Can't create new Schedules"
            logger.error(message)
            abort(403, message)

    def _perform_create(self, data):
        self._check_schedules_limit()
        created = super()._perform_create(data)
        schedule_message = f"Schedule created [Workspaces: {data['workspaces']} - description: {data['description']} crontab: {data['crontab']}]"
        logger.info(schedule_message)
        return created

    @route('/count_schedulers', methods=['GET'])
    def count_schedulers(self):
        """
        ---
        get:
          tags: ["Scheduler"]
          summary: Counts schedulers by type
          responses:
            200:
              description: Counts of schedulers by type
              content:
                application/json:
                  schema:
                    type: object
                    properties:
                      cloud_agent_schedulers:
                        type: integer
                        description: Count of Cloud Agent Schedulers
                      agent_schedulers:
                        type: integer
                        description: Count of Agent Schedulers
        """
        counts = db.session.query(
            SchedulerGeneric.type,
            db.func.count(SchedulerGeneric.id).label('count')
        ).group_by(SchedulerGeneric.type).all()

        result = {
            'cloud_agent_schedulers': 0,
            'agent_schedulers': 0,
        }

        for scheduler_type, count in counts:
            if scheduler_type == 'cloud_agent':
                result['cloud_agent_schedulers'] = count
            elif scheduler_type == 'agent':
                result['agent_schedulers'] = count

        return jsonify(result)


SchedulerView.register(schedule_api)
