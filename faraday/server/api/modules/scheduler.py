# Standard library imports
from datetime import datetime, timezone as dt_timezone
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
    pre_load,
    post_load,
    validate,
    validates_schema,
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
from faraday.server.utils.schedules import (
    SCHEDULE_TYPE_CRON,
    SCHEDULE_TYPE_ONCE,
    SCHEDULE_TYPES,
    to_aware,
    to_naive_utc,
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


# Fields that don't apply to each schedule_type, cleared when a schedule switches to it
_UNUSED_FIELDS_BY_SCHEDULE_TYPE = {
    SCHEDULE_TYPE_CRON: ('run_at',),
    SCHEDULE_TYPE_ONCE: ('crontab', 'start_date'),
}


class ScheduleDateTimeField(fields.AwareDateTime):
    """
    ISO 8601 datetime that must include a UTC offset (naive values are rejected,
    they would be ambiguous). Loads as naive UTC, the storage format; dumps with
    offset, in the schedule timezone.
    """
    default_error_messages = {
        'invalid_awareness': 'Must include a UTC offset, e.g. 2026-10-14T04:00:00-03:00.',
    }

    def _deserialize(self, value, attr, data, **kwargs):
        return to_naive_utc(super()._deserialize(value, attr, data, **kwargs))

    def _serialize(self, value, attr, obj, **kwargs):
        if value is None:
            return None
        return to_aware(value, dateutil.tz.gettz(obj.timezone) or dt_timezone.utc).isoformat()


class SchedulerSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    description = fields.String(required=True)
    # Required only for 'cron' schedules (see validate_schedule_type)
    crontab = fields.String(required=False,
                            allow_none=True,
                            metadata={"example": "10 * 10 * *"},
                            validate=[validate.Regexp(
                                r"^(((([1-5]?\d(-([1-5]?\d))?|\*)(\/(\d+))?),?)+)\ (((((2[0-3]|1?\d)(-(2["
                                r"0-3]|1?\d))?|\*)(\/(\d+))?),?)+)\ (((((3[01]|[12]?\d)(-(3[01]|[12]?\d))?|\*)(\/("
                                r"\d+))?),?)+)\ (((((1[0-2]|\d)(-(1[0-2]|\d))?|\*)(\/(\d+))?),?)+)\ (((([0-6](-(["
                                r"0-6]))?(#[1-5])?|\*)(\/(\d+))?),?)+)$",
                                0,
                                error='Invalid format, Please use basic crontab format, Example: 10 * 10 * *'),
                                check_crontab])
    timezone = fields.String(required=True, validate=check_timezone)
    schedule_type = fields.String(required=False, validate=validate.OneOf(SCHEDULE_TYPES),
                                  metadata={"example": SCHEDULE_TYPE_CRON})
    start_date = ScheduleDateTimeField(required=False, allow_none=True,
                                       metadata={"example": "2026-10-14T04:00:00-03:00"})
    run_at = ScheduleDateTimeField(required=False, allow_none=True,
                                   metadata={"example": "2026-10-14T04:00:00-03:00"})
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
            'schedule_type',
            'start_date',
            'run_at',
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

    @pre_load
    def blank_crontab_as_none(self, data, **kwargs):
        # A 'once' schedule has no crontab; clients may send it empty instead of null
        if isinstance(data, dict) and data.get('crontab') == '':
            data = {**data, 'crontab': None}
        return data

    def _resulting_value(self, data, key, default=None):
        """Value of key once data is applied over the schedule being updated (if any)."""
        if key in data:
            return data[key]
        schedule = self.context.get('object')
        if schedule is not None:
            return getattr(schedule, key, default)
        return default

    @validates_schema
    def validate_schedule_type(self, data, **kwargs):
        schedule_type = self._resulting_value(data, 'schedule_type') or SCHEDULE_TYPE_CRON
        if schedule_type == SCHEDULE_TYPE_CRON:
            if not self._resulting_value(data, 'crontab'):
                raise ValidationError('Missing data for required field.', field_name='crontab')
            return

        run_at = self._resulting_value(data, 'run_at')
        if run_at is None:
            raise ValidationError('Missing data for required field.', field_name='run_at')
        # Only an active schedule that is being (re)scheduled has to point to the future: editing
        # e.g. the description of a 'once' schedule that already ran must still be possible.
        creating = self.context.get('object') is None
        rescheduling = any(key in data for key in ('run_at', 'active', 'schedule_type'))
        active = self._resulting_value(data, 'active', True)
        if active and (creating or rescheduling) and run_at <= datetime.utcnow():
            raise ValidationError('Must be in the future.', field_name='run_at')

    @post_load
    def clear_unused_fields(self, data, **kwargs):
        if 'schedule_type' in data:
            for key in _UNUSED_FIELDS_BY_SCHEDULE_TYPE[data['schedule_type']]:
                data[key] = None
        return data

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
        schedule_message = f"Schedule created [Workspaces: {data['workspaces']} - description: {data['description']} crontab: {data.get('crontab')}]"
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
