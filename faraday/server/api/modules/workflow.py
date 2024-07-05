# Standard library imports
import datetime
import json
import logging
import re

# Related third party imports
import flask
from flask import Blueprint, request, Response
from flask_classful import route
from marshmallow import fields, validate, validates_schema, ValidationError, post_dump
from sqlalchemy import exists

# Local application imports
from faraday.server.api.base import (
    AutoSchema,
    ReadWriteView,
)
from faraday.server.models import (
    db,
    Workflow,
    Action,
    Condition,
    WorkflowExecution,
    Workspace,
    Pipeline,
)
from faraday.server.schemas import SelfNestedField, MetadataSchema

workflow_api = Blueprint('workflow_api', __name__)
logger = logging.getLogger(__name__)

vuln_lookup = {
        "confirmed": {"type": "bool", "replace": True, "append": False},
        "data": {"type": "string", "replace": True, "append": False},
        "description": {"type": "string", "replace": True, "append": False},
        "ease_of_resolution": {"type": "string", "replace": True, "append": False,
                               "valid": [
                                   'trivial',
                                   'simple',
                                   'moderate',
                                   'difficult',
                                   'infeasible'
                               ]},
        "impact_accountability": {"type": "bool", "replace": True, "append": False},
        "impact_availability": {"type": "bool", "replace": True, "append": False},
        "impact_confidentiality": {"type": "bool", "replace": True, "append": False},
        "impact_integrity": {"type": "bool", "replace": True, "append": False},
        "name": {"type": "string", "replace": True, "append": False},
        "policy_violations": {"type": "policy_violations", "replace": True, "append": True},
        "references": {"type": "references", "replace": False, "append": True},
        "resolution": {"type": "string", "replace": True, "append": False},
        "severity": {
            "type": "string",
            "replace": True,
            "append": False,
            "valid": [
                'critical',
                'high',
                'medium',
                'low',
                'informational',
                'unclassified',
            ]},
        "status": {"type": "string", "replace": True, "append": False,
                   "valid": [
                       'open',
                       'closed',
                       're-opened',
                       'risk-accepted'
                   ]},
    }

fields_lookup = {
    "host": {
        "description": {"type": "string", "replace": True, "append": False},
        "hostnames": {"type": "hostnames", "replace": True, "append": True},
        "ip": {"type": "string", "replace": True, "append": False},
        "os": {"type": "string", "replace": True, "append": False},
        "owned": {"type": "bool", "replace": True, "append": False},
    },
    "vulnerability": vuln_lookup,
    "vulnerability_web": vuln_lookup
}


OPERATORS = {
    # Operators which accept a single argument.
    'is_null': lambda f: f is None,
    'is_not_null': lambda f: f is not None,
    # Operators which accept two arguments.
    '==': lambda f, a: f == a,
    '!=': lambda f, a: f != a,
    '>': lambda f, a: f > a,
    '<': lambda f, a: f < a,
    '>=': lambda f, a: f >= a,
    '<=': lambda f, a: f <= a,
    'in': lambda f, a: a in f,
    'not_in': lambda f, a: a not in f,
}

all_valid_operators = list(OPERATORS.keys())
equals_not_equals = [
    '==',
    '!='
]
in_not_in = [
    "in",
    "not_in"
]
string_operators = [
    '==',
    '!=',
    'in'
]
bool_operators = [
    '=='
]
numeric_operators = [
    '==',
    '!=',
    '>',
    '<',
    '>=',
    '<='
]
null_not_null = [
    'is_null',
    'is_not_null'
]

rules_attributes = {
    "host": [
        {"name": "ip", "display_name": "IP", "type": "string", "operators": string_operators},
        {"name": "description", "display_name": "Description", "type": "string", "operators": string_operators},
        {"name": "os", "display_name": "OS", "type": "string", "operators": string_operators},
        {"name": "owned", "display_name": "Owned", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "hostnames", "display_name": "Hostnames", "type": "string", "operators": in_not_in},
        {"name": "update_date", "display_name": "Last Modified", "type": "datetime", "operators": numeric_operators},

        {"name": "importance", "display_name": "Importance", "type": "int", "operators": numeric_operators},
        {"name": "open_service_count", "display_name": "Open Services", "type": "int", "operators": numeric_operators},
        {"name": "vulnerability_count", "display_name": "Vulns", "type": "int", "operators": numeric_operators},
        {"name": "create_date", "display_name": "Creation Time", "type": "datetime", "operators": numeric_operators},
        {"name": "mac", "display_name": "MAC", "type": "string", "operators": string_operators},
        {"name": "creator/username", "display_name": "Owner", "type": "string", "operators": string_operators},
        {"name": "id", "display_name": "id", "type": "int", "operators": numeric_operators},
        {"name": "service/name", "display_name": "Service Name", "type": "string", "operators": string_operators},
        {"name": "service/port", "display_name": "Service Port", "type": "int", "operators": numeric_operators},
        {"name": "service/status", "display_name": "Service Status", "type": "string", "operators": equals_not_equals,
         "valid": (
             "open",
             "closed",
             "filtered"
         )},
        {"name": "service/version", "display_name": "Service Version", "type": "string", "operators": string_operators},
    ],
    "vulnerability": [
        {"name": "name", "display_name": "Name", "type": "string", "operators": string_operators},
        {"name": "confirmed", "display_name": "Confirmed", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "description", "display_name": "Description", "type": "string", "operators": string_operators},
        {"name": "data", "display_name": "Data", "type": "string", "operators": string_operators},
        {"name": "cwe", "display_name": "CWE", "type": "cwe", "operators": in_not_in},
        {"name": "cve", "display_name": "CVE", "type": "string", "operators": in_not_in},
        {"name": "resolution", "display_name": "Resolution", "type": "string", "operators": string_operators},
        {"name": "create_date", "display_name": "Create Date", "type": "datetime", "operators": numeric_operators},
        {"name": "update_date", "display_name": "Update Date", "type": "datetime", "operators": numeric_operators},
        {"name": "ease_of_resolution", "display_name": "Ease of Resolution", "type": "string", "operators": equals_not_equals, "valid": ('trivial', 'simple', 'moderate', 'difficult', 'infeasible')},
        {"name": "severity", "display_name": "Severity", "type": "string", "operators": equals_not_equals, "valid": ('critical', 'high', 'medium', 'low', 'informational', 'unclassified')},
        {"name": "status", "display_name": "Status", "type": "string", "operators": equals_not_equals, "valid": ('open', 'closed', 're-opened', 'risk-accepted')},
        {"name": "impact_accountability", "display_name": "Impact Accountability", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "impact_availability", "display_name": "Impact Availability", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "impact_confidentiality", "display_name": "Impact Confidentiality", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "impact_integrity", "display_name": "Impact Integrity", "type": "bool", "operators": bool_operators, "valid": ("true", "false")},
        {"name": "tool", "display_name": "Tool", "operators": string_operators, "type": "string"},
        {"name": "external_id", "display_name": "External ID", "operators": string_operators, "type": "string"},
        {"name": "cvss2_base_score", "display_name": "CVSS2 Base Score", "operators": numeric_operators, "type": "float"},
        {"name": "cvss3_base_score", "display_name": "CVSS3 Base Score", "operators": numeric_operators, "type": "float"},
        {"name": "hostnames", "display_name": "Hostnames", "type": "string", "operators": in_not_in},
        {"name": "path", "display_name": "Path", "type": "string", "operators": string_operators},
        {"name": "service/name", "display_name": "Service Name", "type": "string", "operators": string_operators},
        {"name": "host/ip", "display_name": "Asset IP", "type": "string", "operators": string_operators},
        {"name": "evidence", "display_name": "Evidence", "type": "null_or_not", "operators": null_not_null},
        {"name": "host/os", "display_name": "Asset OS", "type": "string", "operators": string_operators},
        {"name": "id", "display_name": "ID", "type": "int", "operators": numeric_operators},
        {"name": "method", "display_name": "Method", "type": "string", "operators": equals_not_equals, "valid": ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "CONNECT")},
        {"name": "query_string", "display_name": "Query String", "type": "string", "operators": string_operators},
        {"name": "status_code", "display_name": "Status Code", "type": "int", "operators": numeric_operators},
        {"name": "service_id", "display_name": "Vulnerability Type", "type": "vuln_type", "operators": equals_not_equals, "valid": ("Vulnerability", "Web Vulnerability")},
        {"name": "website", "display_name": "Website", "type": "string", "operators": string_operators},
        {"name": "request", "display_name": "Request", "type": "string", "operators": string_operators},
        {"name": "response", "display_name": "Response", "type": "string", "operators": string_operators},
        {"name": "service/port", "display_name": "Service Port", "type": "int", "operators": numeric_operators},
    ]
}

order_regex = re.compile(r"^$|^\d+(-\d+)*$")

WORKFLOW_LIMIT = 2


class PipelineSchema(AutoSchema):
    id = fields.Integer(dump_only=True)
    name = fields.String(default="")
    description = fields.String(default="")
    jobs_order = fields.String(required=False)
    jobs = fields.List(fields.Nested(lambda: JobSchema(exclude=('pipelines',))), dump_only=True)
    enabled = fields.Boolean(default=False)
    workspace_id = fields.Integer(required=False, allow_none=True)
    jobs_ids = fields.List(fields.Integer, required=False, load_only=True)
    running = fields.Boolean(dump_only=True)

    class Meta:
        model = Pipeline


class JobSchema(AutoSchema):
    MODELS = ("vulnerability", "vulnerability_web", "host", "service")

    id = fields.Integer(dump_only=True)
    name = fields.String()
    description = fields.String(default='')
    model = fields.String(required=True, validate=validate.OneOf(MODELS))
    enabled = fields.Boolean(default=True)
    conditions = fields.List(fields.Nested(lambda: ConditionSchema()), dump_only=True, data_key="rules")
    conditions_json = fields.List(fields.Dict, required=True, load_only=True, data_key="rules_json")
    actions = fields.List(fields.Nested(lambda: TaskwfSchema()), dump_only=True, data_key="tasks")
    pipelines = fields.List(fields.Nested(lambda: PipelineSchema(exclude=('jobs',))), dump_only=True)
    actions_ids = fields.List(fields.Integer, required=True, load_only=True, data_key="tasks_ids")
    metadata = SelfNestedField(MetadataSchema())

    @post_dump
    def clean_conditions(self, data, many, **kwargs):
        clean_conditions = [x for x in data.get("rules") if x.get("is_root") is True]
        data["rules"] = clean_conditions
        return data

    class Meta:
        model = Workflow


class ConditionSchema(AutoSchema):
    TYPES = ('and', 'or', 'xor', 'leaf')

    type = fields.String(required=True, validate=validate.OneOf(TYPES))
    parent_id = fields.Integer(required=False)
    children = fields.List(fields.Nested(lambda: ConditionSchema()))
    field = fields.String(default=None, allow_none=True)
    operator = fields.String(default=None, allow_none=True, validate=validate.OneOf(OPERATORS))
    data = fields.String(default=None, allow_none=True)
    workflow_id = fields.Integer(dump_only=True, data_key="job_id")
    is_root = fields.Boolean(default=False)

    @validates_schema
    def validate_data(self, data, **kwargs):
        if data["type"] == "leaf":
            if not all((data.get("field"), data.get("operator"), data.get("data"))):
                raise ValidationError("Missing fields/operator/data for leaf type condition")

    class Meta:
        model = Condition


class TaskwfSchema(AutoSchema):
    COMMANDS = ("UPDATE", "DELETE", "ALERT", "APPEND")
    TARGETS = ("asset", '')

    id = fields.Integer(dump_only=True)
    name = fields.String(required=False, allow_none=True)
    description = fields.String(required=False, default='')
    command = fields.String(required=True, validate=validate.OneOf(COMMANDS))
    field = fields.String(required=False, allow_none=True)
    value = fields.String(required=False, allow_none=True)
    custom_field = fields.Boolean(required=False, default=False)
    job_id = fields.Integer(required=False, allow_none=True)
    target = fields.String(required=False, allow_none=True, default='', validate=validate.OneOf(TARGETS))

    @validates_schema
    def validate_data(self, data, **kwargs):
        if "command" in data and data["command"] != "DELETE":
            if not data.get("field"):
                raise ValidationError("\"field\" missing")
            if not data.get("value"):
                raise ValidationError("\"value\" missing")

    class Meta:
        model = Action


class WorkflowExecutionSchema(AutoSchema):
    id = fields.String(dump_only=True)
    successful = fields.Boolean(required=True)
    message = fields.String(required=True)
    object_and_id = fields.String(required=True)

    class Meta:
        model = WorkflowExecution


def _create_object_condition(workflow, condition, parent_id: int = None):
    result = ConditionSchema().load(condition)
    new_condition = Condition(
        field=result.get("field"),
        operator=result.get("operator"),
        data=result.get("data"),
        type=result.get("type"),
        workflow_id=workflow.id,
        parent_id=parent_id,
        is_root=parent_id is None
    )
    db.session.add(new_condition)
    db.session.commit()
    return new_condition


def create_condition_from_json(workflow, jsondata, parent_id: int = None):
    new_object = None
    for condition in jsondata:
        if condition.get("type") == "leaf":
            new_object = _create_object_condition(workflow, condition, parent_id)
        elif condition.get("type") in ("and", "or", "xor"):
            new_object = _create_object_condition(workflow, condition, parent_id)
            create_condition_from_json(workflow, condition.get("children"), new_object.id)
        else:
            raise ValueError("Incorrect condition type")
    return new_object


def check_if_field_in_model(data):
    model = data.get("model") if isinstance(data, dict) else data.model
    if model is None:
        return flask.abort(403, "Invalid model")
    for action in data["actions"] if isinstance(data, dict) else data.actions:
        if action.custom_field is True or action.command == "DELETE":
            continue
        if action.field not in fields_lookup.get(model):
            if action.target == "asset" and action.field in fields_lookup.get("host"):
                continue
            if not isinstance(data, dict):
                db.session.rollback()
            return flask.abort(400, f"Field [{action.field}] in action id: [{action.id}] "
                                    f"not compatible with workflow model "
                                    f"\"{data['model'] if isinstance(data, dict) else data.model}\"")


def clean_export_conds(_json):
    new_condition = []
    for cond in _json:
        cond.pop("update_date")
        cond.pop("parent_id")
        cond.pop("job_id")
        cond.pop("id")
        cond.pop("is_root")
        cond.pop("create_date")

        if cond.get("type") != "leaf":
            cond.pop("operator")
            cond.pop("data")
            cond.pop("field")

        if "children" in cond and cond["children"] is not []:
            cond["children"] = clean_export_conds(cond["children"])
        new_condition.append(cond)
    return new_condition


def _clone_actions(actions_json):
    actions = []
    for action in actions_json:
        action_loaded = TaskwfSchema().load(action)
        new_ac = Action(
                name=action_loaded.get("name"),
                value=action_loaded.get("value"),
                field=action_loaded.get("field"),
                command=action_loaded.get("command"),
                description=action_loaded.get("description"),
                custom_field=action_loaded.get("custom_field"),
            )
        db.session.add(new_ac)
        actions.append(new_ac)
    db.session.commit()
    return actions


class JobView(ReadWriteView):
    route_base = 'jobs'
    model_class = Workflow
    schema_class = JobSchema

    def _perform_create(self, data, **kwargs):

        workflows_in_use = db.session.query(Workflow).count()
        workflow_limit = WORKFLOW_LIMIT
        if workflows_in_use >= workflow_limit:
            message = "Workflow limit reached. Can't create new Workflows"
            logger.error(message)
            return flask.abort(403, message)

        actions_ids = data.pop('actions_ids', [])

        data["actions"] = Action.query.filter(Action.id.in_(actions_ids)).all()
        check_if_field_in_model(data)

        conditions_json = data.pop("conditions_json", [])

        created = super()._perform_create(data)

        try:
            create_condition_from_json(created, conditions_json)
        except Exception as e:
            logger.error(f"Error while creating conditions - {e}")
            db.session.delete(created)
            db.session.commit()
            return flask.abort(400, "Error During Condition Creation, Check json")

        workflow_message = f"Job created [model: {data['model']}] "
        logger.info(workflow_message)
        return created

    def _update_object(self, obj, data, **kwargs):
        data.pop("conditions", None)
        data.pop("actions", None)
        data.pop("executions", None)

        for (key, value) in data.items():
            if key in ("conditions_json", "actions_ids"):
                continue
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, already_notified=False):

        actions_ids = data.pop('actions_ids', [])
        if actions_ids:
            db.session.begin_nested()
            obj.actions = Action.query.filter(Action.id.in_(actions_ids)).all()
            check_if_field_in_model(obj)

        conditions_json = data.pop("conditions_json", [])
        if conditions_json:
            for condition_in_db in obj.conditions:
                db.session.delete(condition_in_db)

            try:
                create_condition_from_json(obj, conditions_json)
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error while creating conditions - {e}")
                return flask.abort(400, "Error During Condition Creation, Check json")
        db.session.commit()

        super()._perform_update(object_id, obj, data)

    @staticmethod
    def _get_workflow(job_id):
        workflow = db.session.query(Workflow)\
            .filter(Workflow.id == job_id)\
            .first()
        if not workflow:
            flask.abort(404)

        workflow_json = JobSchema().dump(workflow)

        workflow_json.pop("create_date")
        workflow_json.pop("metadata")
        workflow_json.pop("id")
        workflow_json.pop("update_date")

        return workflow_json

    @route('/<int:job_id>/executions', methods=['GET'])
    def get_executions(self, job_id):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Get the executions of a job"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: WorkflowExecutionSchema
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        workflow = db.session.query(Workflow) \
            .filter(Workflow.id == job_id) \
            .first()
        if not workflow:
            flask.abort(404)
        serialized_executions = WorkflowExecutionSchema().dump(workflow.executions, many=True)
        return flask.jsonify(serialized_executions)

    @route('/<int:job_id>/tasks', methods=['GET'])
    def get_actions(self, job_id):
        """
        ---
        get:
          tags: ["Job", "Action"]
          summary: "Get the actions associated to a job"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: TaskwfSchema
        tags: ["Job", "Action"]
        responses:
          200:
            description: Ok
        """
        workflow = db.session.query(Workflow) \
            .filter(Workflow.id == job_id) \
            .first()
        if not workflow:
            flask.abort(404)
        serialized_actions = TaskwfSchema().dump(workflow.actions, many=True)
        return flask.jsonify(serialized_actions)

    @route('/<int:job_id>/conditions', methods=['GET'])
    def get_conditions(self, job_id):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Get the conditions of a job"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: ConditionSchema
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        workflow = db.session.query(Workflow) \
            .filter(Workflow.id == job_id) \
            .first()
        if not workflow:
            flask.abort(404)

        serialized_conditions = ConditionSchema().dump(workflow.root_condition)
        return flask.jsonify(serialized_conditions)

    @route('/<int:job_id>/enabled', methods=['GET'])
    def enabled(self, job_id):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Get the enabled status of a job"
          responses:
            200:
              description: Ok
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        workflow = db.session.query(Workflow)\
            .filter(Workflow.id == job_id)\
            .first()
        if not workflow:
            flask.abort(404)

        return flask.jsonify(workflow.enabled)

    # @api_method_validation
    # @route('/order', methods=['POST'])
    # def set_wf_order(self, workspace_name):
    #     """
    #     ---
    #     post:
    #       tags: ["Job", "Workspace"]
    #       summary: "Sets the order of execution of jobs"
    #       responses:
    #         200:
    #           description: Ok
    #     tags: ["Job", "Workspace"]
    #     responses:
    #       200:
    #         description: Ok
    #     """
    #     workspace = db.session.query(Workspace).filter(Workspace.name == workspace_name).first()
    #     if not workspace:
    #         flask.abort(404)
    #
    #     if request.json.get("wf_order") is not None:
    #         ids = request.json.get("wf_order")
    #
    #         if isinstance(ids, str):
    #             match = re.match(order_regex, ids)
    #             if match is not None:
    #                 workspace.workflows_order = match.group(0)
    #                 db.session.add(workspace)
    #                 db.session.commit()
    #                 return 200
    #             else:
    #                 flask.abort(400)
    #         else:
    #             # Check for repeated entries
    #             if len(ids) != len(set(ids)):
    #                 flask.abort(400)
    #
    #             wfs_ids_str = [str(x) for x in ids]
    #             order_string = "-".join(wfs_ids_str)
    #             match = re.match(order_regex, order_string)
    #             if match is not None:
    #                 workspace.workflows_order = match.group(0)
    #                 db.session.add(workspace)
    #                 db.session.commit()
    #                 return 200
    #             else:
    #                 flask.abort(400)
    #     else:
    #         flask.abort(400)

    @route('/<int:job_id>/export_job', methods=['GET'])
    def export_wf(self, job_id):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Export job as json"
          responses:
            200:
              description: Ok
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        workflow_json = self._get_workflow(job_id)

        actions_json = workflow_json.pop("actions")
        conditions_json = workflow_json.pop("conditions")

        workflow_json["actions_ids"] = [x.get("id") for x in actions_json]

        workflow_json["conditions_json"] = clean_export_conds(conditions_json)

        return Response(json.dumps(workflow_json, sort_keys=True, indent=4),
                        mimetype='application/json',
                        headers={
                            'Content-Disposition':
                                f'attachment;'
                                f'filename='
                                f'Job-{workflow_json.get("name", "Unnamed")}-{str(datetime.datetime.now())}.json'
                        })

    @route('/import_job', methods=['POST'])
    def import_wf(self):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Import job from json"
          responses:
            201:
              description: Ok
        tags: ["Job"]
        responses:
          201:
            description: Ok
        """
        json_file = None
        if len(request.files) == 0:
            flask.abort(400)
        created = None
        for file in request.files.values():
            try:
                json_file = json.loads(file.read())
            except Exception:
                flask.abort(400, "Error while parsing file")
            created = self._perform_create(json_file)
        serialized_workflow = JobSchema().dump(created)
        return flask.jsonify(serialized_workflow)

    @route('/rules/attributes', methods=['GET'])
    def get_attribs(self):
        """
        ---
        get:
          tags: ["Job"]
          summary: "Get the Attributes for rules"
          responses:
            200:
              description: Ok
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        return flask.jsonify(rules_attributes)

    @route('/<int:job_id>/clone', methods=['POST'])
    def clone_wf(self, job_id):
        """
        ---
        post:
          tags: ["Job"]
          summary: "Clone job"
          responses:
            200:
              description: Ok
        tags: ["Job"]
        responses:
          200:
            description: Ok
        """
        workflow_json = self._get_workflow(job_id)
        workflow_json.pop("pipelines")

        actions_json = workflow_json.pop("tasks", None)
        conditions_json = workflow_json.pop("rules", None)

        if actions_json:
            new_actions = _clone_actions(actions_json)
            workflow_json["actions_ids"] = [x.id for x in new_actions]
        if conditions_json:
            workflow_json["conditions_json"] = clean_export_conds(conditions_json)

        # Copy [num]
        num = 1
        while True:
            name = f"{workflow_json['name']} - Copy {num}"
            if db.session.query(exists().where(Workflow.name == name)).scalar():
                num += 1
            else:
                break

        workflow_json["name"] = name

        created = self._perform_create(workflow_json)
        serialized_workflow = JobSchema().dump(created)
        return flask.jsonify(serialized_workflow)


class TaskView(ReadWriteView):
    route_base = 'tasks'
    model_class = Action
    schema_class = TaskwfSchema

    @route('/<int:task_id>/jobs', methods=['GET'])
    def get_workflows(self, task_id):
        """
        ---
        get:
          tags: ["Action"]
          summary: "Get the jobs associated to a task"
          responses:
            200:
              description: Ok
              content:
                application/json:
                  schema: JobSchema
        tags: ["Action"]
        responses:
          200:
            description: Ok
        """
        action = Action.query.filter(Action.id == task_id).first()
        if not action:
            flask.abort(404)
        serialized_workflows = JobSchema().dump(action.workflows, many=True)
        return flask.jsonify(serialized_workflows)

    @route('/fields', methods=['GET'])
    def get_fields(self):
        """
        ---
        get:
          tags: ["Action"]
          summary: "Get the valid fields for tasks"
          responses:
            200:
              description: Ok
        tags: ["Action"]
        responses:
          200:
            description: Ok
        """
        return flask.jsonify(fields_lookup)


class PipelineView(ReadWriteView):
    route_base = 'pipelines'
    model_class = Pipeline
    schema_class = PipelineSchema

    def _perform_create(self, data, **kwargs):
        jobs_ids = data.pop("jobs_ids", None)
        if jobs_ids is not None:
            data["jobs"] = Workflow.query.filter(Workflow.id.in_(jobs_ids)).all()

        workspace_id = data.get("workspace_id", None)
        if workspace_id is not None:
            ws = db.session.query(Workspace).filter(Workspace.id == workspace_id).first()
            if ws is not None:
                data["enabled"] = not ws.pipelines

        return super()._perform_create(data, **kwargs)

    def _update_object(self, obj, data, **kwargs):
        data.pop("jobs", None)
        data.pop("enabled", None)

        for (key, value) in data.items():
            if key == "jobs_ids":
                continue
            setattr(obj, key, value)

    def _perform_update(self, object_id, obj, data, workspace_name=None, partial=False, already_notified=False):

        if partial:
            new_ws = data.get("workspace_id", None)
            if new_ws:
                ws = db.session.query(Workspace).filter(Workspace.id == new_ws).first()
                if ws is not None:
                    data["enabled"] = not ws.pipelines

        jobs_ids = data.pop("jobs_ids", None)
        if jobs_ids is not None:
            db.session.begin_nested()
            obj.jobs = Workflow.query.filter(Workflow.id.in_(jobs_ids)).all()
            db.session.add(obj)
            db.session.commit()
        return super()._perform_update(object_id, obj, data, partial)

    @staticmethod
    def _get_pipeline(pipeline_id):
        pipeline = db.session.query(Pipeline) \
            .filter(Pipeline.id == pipeline_id) \
            .first()
        if not pipeline:
            flask.abort(404)

        pipeline_json = PipelineSchema().dump(pipeline)

        pipeline_json.pop("enabled", None)
        pipeline_json.pop("create_date", None)
        pipeline_json.pop("metadata", None)
        pipeline_json.pop("id", None)
        pipeline_json.pop("update_date", None)

        return pipeline_json

    @route('/<int:pipeline_id>/export', methods=['GET'])
    def export_pipeline(self, pipeline_id):
        """
        ---
        get:
          tags: ["Pipeline"]
          summary: "Export pipeline as json"
          responses:
            200:
              description: Ok
        tags: ["Pipeline"]
        responses:
          200:
            description: Ok
        """
        pipeline_json = self._get_pipeline(pipeline_id)
        jobs_json = pipeline_json.pop("jobs", None)

        pipeline_json["jobs_ids"] = [x.get("id") for x in jobs_json]

        return pipeline_json

    @route('/<int:pipeline_id>/clone', methods=['POST'])
    def export_pl(self, pipeline_id):
        """
        ---
        post:
          tags: ["Pipeline"]
          summary: "Clone pipeline"
          responses:
            200:
              description: Ok
        tags: ["Pipeline"]
        responses:
          200:
            description: Ok
        """
        pipeline_json = self._get_pipeline(pipeline_id)
        pipeline_json.pop("running", None)
        jobs_json = pipeline_json.pop("jobs", None)

        pipeline_json["jobs_ids"] = [x.get("id") for x in jobs_json]

        # Copy [num]
        num = 1
        while True:
            name = f"{pipeline_json['name']} - Copy {num}"
            if db.session.query(exists().where(Pipeline.name == name)).scalar():
                num += 1
            else:
                break

        pipeline_json["name"] = name
        pipeline_json["enabled"] = False

        created = self._perform_create(pipeline_json)
        serialized_pl = PipelineSchema().dump(created)
        return flask.jsonify(serialized_pl)

    @route('/<int:pipeline_id>/run', methods=['POST'])
    def run_all(self, pipeline_id):
        """
        ---
        post:
          tags: ["Pipeline"]
          summary: "Run pipeline with historical data"
          responses:
            200:
              description: Ok
        tags: ["Pipeline"]
        responses:
          200:
            description: Ok
        """
        pipeline = db.session.query(Pipeline) \
            .filter(Pipeline.id == pipeline_id) \
            .first()
        if not pipeline:
            flask.abort(404)

        if pipeline.workspace_id is None:
            flask.abort(400, "Pipeline doesn't have an assigned Workspace")

        if pipeline.running is True:
            flask.abort(400, "Pipeline already running")

        from faraday.server.tasks import workflow_task  # pylint: disable=import-outside-toplevel
        # TODO: Check if there is an active workflow
        # TODO: Implement bulk
        workflow_task.delay(None,
                            None,
                            pipeline.workspace.id,
                            None,
                            True,
                            pipeline.id)

        return 200

    @route('/<int:pipeline_id>/disable', methods=['POST'])
    def disable(self, pipeline_id):
        """
        ---
        post:
          tags: ["Pipeline"]
          summary: "Disable Pipeline"
          responses:
            200:
              description: Ok
        tags: ["Pipeline"]
        responses:
          200:
            description: Ok
        """
        pipeline = db.session.query(Pipeline) \
            .filter(Pipeline.id == pipeline_id) \
            .first()
        if not pipeline:
            flask.abort(404)

        pipeline.enabled = False
        db.session.add(pipeline)
        db.session.commit()

        return PipelineSchema().dump(pipeline)

    @route('/<int:pipeline_id>/enable', methods=['POST'])
    def enable(self, pipeline_id):
        """
        ---
        post:
          tags: ["Pipeline"]
          summary: "Enable Pipeline and Disable all others in same Workspace"
          responses:
            200:
              description: Ok
        tags: ["Pipeline"]
        responses:
          200:
            description: Ok
        """
        pipeline = db.session.query(Pipeline) \
            .filter(Pipeline.id == pipeline_id) \
            .first()
        if not pipeline:
            flask.abort(404)
        if pipeline.workspace_id is None:
            flask.abort(400, "Pipeline doesn't have an assigned Workspace")

        ws = pipeline.workspace
        pipeline.enabled = True
        db.session.add(pipeline)
        for pl in ws.pipelines:
            if pl != pipeline:
                pl.enabled = False
                db.session.add(pl)
        db.session.commit()

        return PipelineSchema().dump(pipeline)


JobView.register(workflow_api)
TaskView.register(workflow_api)
PipelineView.register(workflow_api)
