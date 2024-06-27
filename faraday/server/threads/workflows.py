"""
Faraday Penetration Test IDE
Copyright (C) 2021  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import logging
import threading
from datetime import datetime
from queue import Empty, Queue

# Related third party imports
from marshmallow import Schema, fields
from sqlalchemy import inspect
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound

# Local application imports
from faraday.server.api.modules.comments import CommentSchema
from faraday.server.api.modules.workflow import (
    WorkflowExecutionSchema,
    OPERATORS,
    fields_lookup,
    rules_attributes,
)
from faraday.server.models import (
    db,
    Host,
    Service,
    VulnerabilityGeneric,
    Workflow,
    WorkflowExecution,
    Workspace,
    Pipeline,
    TagObject,
    Comment,
    CustomFieldsSchema,
)

logger = logging.getLogger(__name__)

WORKFLOW_QUEUE = Queue()
INTERVAL = 0.1

valid_object_types = ("vulnerability", "host", "vulnerability_web")
valid_classes = (Host, VulnerabilityGeneric)


obj_table = {
    "vulnerability": VulnerabilityGeneric,
    "vulnerability_web": VulnerabilityGeneric,
    "host": Host,
    # "service": Service
}


class BooleanSchema(Schema):
    value = fields.Boolean(default=False)


def _get_obj_and_workspace(obj_type, obj_id, ws_id, fields=None, pipeline_id=None):
    logger.debug(f"Get object  {obj_type}-{obj_id} from ws {ws_id}")
    return_if_fail = False, False, False, False
    obj_type = obj_type.lower()

    obj_type = "vulnerability_web" if obj_type == "vulnerabilityweb" else obj_type

    if obj_type not in valid_object_types:
        logger.info("Workflows not supported for this type of object")
        return return_if_fail

    workspace = db.session.query(Workspace).filter(Workspace.id == ws_id).first()
    pipeline = db.session.query(Pipeline).filter(Workspace.id == ws_id, Pipeline.id == pipeline_id).first()\
        if pipeline_id is not None else None

    if obj_type not in obj_table:
        logger.error(f"Invalid object type: {obj_type}")
        return return_if_fail

    query = db.session.query(obj_table[obj_type])

    filters = []
    if obj_type in ("vulnerability", "vulnerability_web"):
        filters.append(VulnerabilityGeneric.workspace == workspace)
        filters.append(VulnerabilityGeneric.id == obj_id)
    elif obj_type == "host":
        filters.append(Host.workspace == workspace)
        filters.append(Host.id == obj_id)
    elif obj_type == "service":
        filters.append(Service.workspace == workspace)
        filters.append(Service.id == obj_id)

    try:
        obj = query.filter(*filters).one()
    except NoResultFound:
        logger.warning(f"Object not found in db - {obj_type}/{obj_id} on {workspace}")
        logger.debug(f"obj_type: {obj_type} - id: {obj_id} - workspace: {workspace}")
        return return_if_fail
    except MultipleResultsFound:
        logger.error("More than one result found")
        logger.debug(f"obj_type: {obj_type} - id: {obj_id} - workspace: {workspace}")
        return return_if_fail

    return obj, obj_type, workspace, fields, pipeline


def _process_field_data(obj, field):

    field = field.split('/')

    for route in field:
        obj_data_in_field = getattr(obj, route, None)
        if obj_data_in_field is None:
            raise ValueError(f"Field \"{route}\" not found in object {obj}")
        if isinstance(obj_data_in_field, db.Model):
            obj = obj_data_in_field
        else:
            field = route
            break
    return obj, field


def _check_leaf(obj, condition):

    obj, field = _process_field_data(obj, condition.field)
    model_data = getattr(obj, field, None)
    if model_data is None:
        raise ValueError(f"Field \"{field}\" not found in object {obj}")

    operator = OPERATORS.get(condition.operator, None)
    if operator is None:
        raise ValueError(f"Operator {condition.operator} not valid")

    class_name = obj.__class__.__name__.lower()
    class_name = "vulnerability" if "web" in class_name else class_name

    data_type = [x.get("type") for x in rules_attributes[class_name] if x.get("name") == field][0]
    data = condition.data

    if data_type == "string":
        data = str(data)
    elif data_type == "int":
        data = int(data)
    elif data_type == "float":
        data = float(data)
    elif data_type == "bool":
        data = BooleanSchema().load({"value": data}).get("value")
    elif data_type == "datetime":
        # convert data formatted as YYYY-MM-DD to datetime date object
        data = datetime.strptime(data, "%Y-%m-%d").date()
        return operator(model_data.date(), data)
    elif data_type == "cwe":
        model_data = [x.name for x in model_data]
        data = str(data)

    return operator(model_data, data)


def _check_condition(obj, condition):
    if condition.type == "leaf":
        try:
            return _check_leaf(obj, condition)
        except Exception as e:
            logger.error(f"Error while checking condition id: {condition.id} - {e}")
            return False
    elif condition.type == "and":
        return all(_check_condition(obj, child) for child in condition.children)
    elif condition.type == "or":
        return any(_check_condition(obj, child) for child in condition.children)
    elif condition.type == "nand":
        return not all(_check_condition(obj, child) for child in condition.children)
    elif condition.type == "nor":
        return not any(_check_condition(obj, child) for child in condition.children)
    else:
        raise ValueError(f"Invalid type: \"{condition.type}\"")


def _create_tag(tags, obj):
    tags = [x.strip() for x in tags.split(",")]
    for tag in tags:
        obj.tags.add(tag)


def _create_comment(value, obj):
    comment_data = CommentSchema().load(
        {
            "object_id": obj.id,
            "object_type": "vulnerability",
            "text": value,
        }
    )
    comment = Comment(
        comment_type="system",
        object_id=comment_data.get("object_id"),
        object_type=comment_data.get("object_type"),
        text=comment_data.get("text"),
        workspace_id=obj.workspace_id
    )
    db.session.add(comment)
    db.session.commit()


def _create_log_comment(text, obj, model):
    model = "vulnerability" if "web" in model else model
    comment_data = CommentSchema().load(
        {
            "object_id": obj.id,
            "object_type": model,
            "text": text,
        }
    )
    comment = Comment(
        comment_type="system",
        object_id=comment_data.get("object_id"),
        object_type=comment_data.get("object_type"),
        text=comment_data.get("text"),
        workspace_id=obj.workspace_id
    )
    db.session.add(comment)
    db.session.commit()


def _modify_custom_field(cf_name, obj, value, append):

    cf = db.session.query(CustomFieldsSchema).filter(CustomFieldsSchema.field_name == cf_name).first()
    if cf is None:
        raise ValueError(f"Custom field \"{cf_name}\" not found in DB")
    cf_type = cf.field_type

    if obj.custom_fields is None:
        obj.custom_fields = {}

    if cf_type in ("string", "markdown"):
        # String/markdown can Replace and Append
        if append is False:
            obj.custom_fields[cf_name] = value
        else:
            current_data = obj.custom_fields.get(cf_name)
            new_data = current_data + f"\n{value}"
            obj.custom_fields[cf_name] = new_data
    if cf_type == "int":
        # Int can Replace
        obj.custom_fields[cf_name] = int(value)
    if cf_type == "list":
        # List can Append
        if append is True:
            if obj.custom_fields == {} or not isinstance(obj.custom_fields[cf_name], list):
                obj.custom_fields[cf_name] = []
            obj.custom_fields[cf_name].append(value)
    if cf_type == "choice":
        # Choice can Replace
        obj.custom_fields[cf_name] = value

    db.session.add(obj)
    db.session.commit()


def _create_reference(value, obj):

    obj.references.add(value)


def _create_policy_violation(value, obj):

    obj.policy_violations.add(value)


def _execute_action(obj, action, workflow):

    # Check if custom field
    if action.custom_field is True:
        _modify_custom_field(action.field, obj, action.value, action.command == "APPEND")
    else:
        if action.command in ("UPDATE", "APPEND"):

            field_type = fields_lookup[workflow.model].get(action.field).get("type")
            can_replace = fields_lookup[workflow.model].get(action.field).get("replace")
            can_append = fields_lookup[workflow.model].get(action.field).get("append")
            valid_values = fields_lookup[workflow.model].get(action.field).get("valid", None)

            if (can_append is False and action.command == "APPEND")\
                    or (can_replace is False and action.command == "UPDATE"):
                raise ValueError(f"Command {action.command} not valid for field {action.field}")

            if valid_values is not None:
                if action.value not in valid_values:
                    raise ValueError(f"Value {action.value} not in valid values for field {action.field}\n"
                                     f"Valid Values: {valid_values}")

            if field_type == "string":
                if can_append is False or (can_replace is True and action.command == "UPDATE"):
                    setattr(obj, action.field, action.value)
                elif can_append is True and action.command == "APPEND":
                    current_data = getattr(obj, action.field)
                    new_data = current_data + f"\n{action.value}"
                    setattr(obj, action.field, new_data)
            elif field_type == "int":
                if can_append is False or (can_replace is True and action.command == "UPDATE"):
                    setattr(obj, action.field, int(action.value))
            elif field_type == "bool":
                if can_append is False or (can_replace is True and action.command == "UPDATE"):
                    value = BooleanSchema().load({"value": action.value}).get("value")
                    setattr(obj, action.field, value)
            elif field_type == "tag":
                if can_append is False or (can_replace is True and action.command == "UPDATE"):
                    # Delete tags in object if set to replace
                    db.session.query(TagObject).filter(TagObject.object_id == obj.id).delete()
                _create_tag(action.value, obj)
            elif field_type == "comment":
                _create_comment(action.value, obj)
            elif field_type == "references":
                _create_reference(action.value, obj)
            elif field_type == "policy_violations":
                _create_policy_violation(action.value, obj)
            db.session.add(obj)
            db.session.commit()

        if action.command == "DELETE":
            db.session.delete(obj)
            db.session.commit()


def _run_workflow(workflow, obj):
    if workflow.root_condition is None:
        raise ValueError("No root condition, Invalid condition tree")
    logger.debug(f"Running conditions of Workflow id: {workflow.id}, Root condition id: {workflow.root_condition}")
    conditions_passed = _check_condition(obj, workflow.root_condition)
    if conditions_passed:
        logger.debug(f"Conditions passed for Workflow id: {workflow.id}, executing {len(workflow.actions)} actions")

        obj_repr = repr(obj)
        message = f"\nJob \"{workflow.name}\" Executed Changes:"
        actions_results = []
        if workflow.actions is not None:
            for action in workflow.actions:
                try:
                    _execute_action(obj, action, workflow)
                    actions_results.append(True)
                    if action.command == "UPDATE":
                        message += f'\nUpdated field "{action.field}" to "{action.value}"'
                    elif action.command == "APPEND":
                        message += f'\nAppended field {action.field}, with "{action.value}"'
                    elif action.command == "DELETE":
                        message += f'\nDeleted object {obj_repr}'
                        break
                except Exception as e:
                    logger.error(f"Action ID: {action.id} Failed to execute. - {e}")
                    actions_results.append(False)
                    message += f"\nTask Execution Failed, Task id {action.id}, Error: {e}"
        logger.debug(f"Tasks that ran without errors / total = {actions_results.count(True)}/{len(workflow.actions)}")
        _create_workflow_execution(workflow, obj_repr, message)
        # if not inspect(obj).deleted and not inspect(obj).detached:
        #     _create_log_comment(message, obj, workflow.model)
        message += "\n"
        return True, message
    else:
        logger.debug(f"Conditions failed for Workflow id: {workflow.id}, skipping")
        _create_workflow_execution(workflow, repr(obj), "Conditions failed, did not execute actions")
        return False, ""


def _create_workflow_execution(workflow, obj_repr, message, error=None):
    result = WorkflowExecutionSchema().load(
        {
            "successful": error is None,
            "message": f"{workflow} ran on object {obj_repr}, {message}\nerrors: {error}",
            "object_and_id": obj_repr
        }
    )
    new_execution = WorkflowExecution(
        successful=result.get("successful"),
        message=result.get("message"),
        workflow=workflow,
        object_and_id=result.get("object_and_id")
    )
    db.session.add(new_execution)
    db.session.commit()
    return new_execution


def _get_workflows(*filter_params):
    return db.session.query(Workflow).filter(*filter_params).all()


def _check_workflows(obj, obj_type, ws, fields=None, pipeline_given=None):
    if False in (obj, obj_type, ws):
        return False, []
    if isinstance(obj, valid_classes):

        if pipeline_given is None:
            # Get pipeline
            if not ws.pipelines:
                logger.debug(f"Workspace {ws.name} has no pipelines")
                return False, []
            else:
                pipeline = next((x for x in ws.pipelines if x.enabled is True), None)
                if pipeline is None:
                    logger.warning("All pipelines disabled")
                    return False, []
        else:
            pipeline = pipeline_given

        workflows = pipeline.jobs
        if any(workflows):
            workflows_count = len(workflows)

            logger.info(f"Running pipeline {pipeline} with {workflows_count} job{'s' if workflows_count > 1 else ''}"
                        f" to run with current object {repr(obj)}, IDs: {[x.id for x in workflows]}")
        else:
            logger.debug(f"No workflows found to run with object: {repr(obj)}")
            return True, []
        workflows_results = []
        pipeline_wf_order = pipeline.jobs_order
        if pipeline_wf_order == "":
            workflows_ids = [x.id for x in workflows]
        else:
            workflows_ids = pipeline_wf_order.split('-')

        workflows_ids = [int(x) for x in workflows_ids if int(x) in [x.id for x in workflows]]

        logger.debug(f"Executing in order: {workflows_ids}")
        comment_log = ""

        for workflow_id in workflows_ids:

            if inspect(obj).deleted or inspect(obj).detached:
                logger.debug("Object deleted by previous workflow, Skipping the rest of the workflows")
                break

            workflow = next((x for x in workflows if x.id == workflow_id), None)
            if workflow is None:
                logger.debug(f"Workflow id {workflow_id} not runnable with current object "
                             f"or invalid/disabled, Skipping")
                continue

            obj_type_cond = "vulnerability" if obj_type == "vulnerability_web" else obj_type
            if workflow.model != obj_type_cond:
                logger.debug(f"Workflow id {workflow_id} not runnable with current object, Skipping")
                continue

            # If none of the conditions check modified fields, skip workflow
            if fields is not None:
                fields_to_check = {condition.field for condition in workflow.conditions}
                if not any(item in fields_to_check for item in fields):
                    logger.info("Skipping workflow, related fields not modified")
                    workflows_results.append(True)
                    continue

            try:
                result, log = _run_workflow(workflow, obj)
                workflows_results.append(result)
                comment_log += log
            except Exception as e:
                workflows_results.append(False)
                logger.error(f"Error while running workflow id [{workflow.id}] - Error: {e}")
                message = "\nError while running workflow, Skipping the rest of the pipeline"
                _create_workflow_execution(workflow, repr(obj), message, e)
                break
        logger.debug(f"Jobs that met conditions and executed actions / Jobs checked total ="
                     f" {workflows_results.count(True)}/{len(workflows)}")

        if not inspect(obj).deleted and not inspect(obj).detached and comment_log:
            _create_log_comment(comment_log, obj, obj_type)

        return True, workflows_results
    else:
        logger.debug("Workflows not supported for this type of object")
        return False, []


def _change_pipeline_running_status(id, status):
    pipeline = db.session.query(Pipeline).filter(Pipeline.id == id).first()
    if pipeline is None:
        raise ValueError("Invalid Pipeline id")
    pipeline.running = status
    db.session.add(pipeline)
    db.session.commit()


def _process_entry(obj, obj_id, ws_id, fields=None, run_all=False, pipeline_id=None):
    if obj and obj_id and ws_id:
        return _check_workflows(*_get_obj_and_workspace(obj, obj_id, ws_id, fields, pipeline_id))
    elif run_all is True:
        logger.info(f"Running all objects with pipeline id {pipeline_id}")

        _change_pipeline_running_status(pipeline_id, True)

        try:
            for obj_key, obj_model in obj_table.items():
                ids = db.session.query(obj_model.id).filter(obj_model.workspace_id == ws_id).all()
                for _id in ids:
                    _process_entry(
                        obj_key,
                        _id[0],
                        ws_id,
                        None,
                        False,
                        pipeline_id if pipeline_id is not None else None
                       )
        except Exception as e:
            logger.error(f"Error while running pipeline\n{e}")
            _change_pipeline_running_status(pipeline_id, False)

        pipeline_name = db.session.query(Pipeline.name).filter(Pipeline.id == pipeline_id).first()[0]
        ws_name = db.session.query(Workspace.name).filter(Workspace.id == ws_id).first()[0]

        _change_pipeline_running_status(pipeline_id, False)
        return True


class WorkflowWorker(threading.Thread):

    def __init__(self, app, workflow_queue, *args, **kwargs):
        threading.Thread.__init__(self, name="WorkflowWorkerThread", daemon=True, *args, **kwargs)
        self.app = app
        self.workflow_queue = workflow_queue
        self.stop_thread = False
        self.__event = threading.Event()

    def stop(self):
        logger.info("Workflow Worker Thread [Stopping...]")
        self.__event.set()

    def run(self):
        logger.info("Workflow Worker Thread [Start]")
        while not self.__event.is_set():
            try:
                entry_data = self.workflow_queue.get(False, timeout=0.1)
                if entry_data:
                    with self.app.app_context():
                        _process_entry(*entry_data)
            except Empty:
                self.__event.wait(INTERVAL)
            except Exception as ex:
                logger.exception(ex)
        logger.info("Workflow Worker Thread [Stop]")
