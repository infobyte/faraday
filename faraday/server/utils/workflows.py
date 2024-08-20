import logging
from datetime import datetime
from functools import lru_cache
from queue import Empty, Queue

import sqlalchemy
# Related third party imports
from marshmallow import Schema, fields
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload, subqueryload
from sqlalchemy.orm.exc import NoResultFound, MultipleResultsFound
from gevent.event import Event

# Local application imports
from faraday.server.api.modules.workflow import (
    OPERATORS,
    fields_lookup,
    rules_attributes,
)
from faraday.server.extensions import socketio
from faraday.server.models import (
    db,
    Host,
    Service,
    VulnerabilityGeneric,
    Workflow,
    Workspace,
    Pipeline,
    CustomFieldsSchema,
)
from faraday.server.utils.reference import create_reference

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

run_all_obj_table = {
    "vulnerability": VulnerabilityGeneric,
    "host": Host,
}


class BooleanSchema(Schema):
    value = fields.Boolean(default=False)


def _get_workspace(ws_id):
    workspace = (db.session.query(Workspace)
                 .options(joinedload(Workspace.pipelines)
                          .subqueryload(Pipeline.jobs)
                          .joinedload(Workflow.conditions, Workflow.actions))
                 .filter(Workspace.id == ws_id).first())
    if workspace is None:
        logger.error(f"Workspace {ws_id} not found")
        return None
    return workspace


def _get_pipeline(pipeline_id: int = None, workspace: Workspace = None, ws_id: int = None) -> Pipeline:
    if pipeline_id is None:
        # Get pipeline
        if not workspace.pipelines:
            logger.debug(f"Workspace {workspace.name} has no pipelines")
            return None
        else:
            pipeline = next((x for x in workspace.pipelines if x.enabled is True), None)
            if pipeline is None:
                logger.warning("All pipelines disabled")
                return None
            return pipeline
    else:
        pipeline = (db.session.query(Pipeline)
                    .options(subqueryload(Pipeline.jobs)
                             .joinedload(Workflow.conditions, Workflow.actions))
                    .filter(Workspace.id == ws_id, Pipeline.id == pipeline_id).first()) \
                    if pipeline_id is not None else None
        if pipeline is None:
            logger.warning(f"Pipeline {pipeline_id} not found")
            return None
        return pipeline


def _get_obj_and_workspace(obj_type, obj_ids, ws_id, fields=None, pipeline_id=None):
    logger.debug(f"Get objects  {obj_type}-{obj_ids} from ws {ws_id}")
    return_if_fail = False, False, False, False, False
    obj_type = obj_type.lower()

    obj_type = "vulnerability_web" if obj_type == "vulnerabilityweb" else obj_type

    if obj_type not in valid_object_types:
        logger.info("Workflows not supported for this type of object")
        return return_if_fail

    workspace = _get_workspace(ws_id)
    if workspace is None:
        return return_if_fail

    pipeline = _get_pipeline(pipeline_id, workspace, ws_id)
    if pipeline is None:
        return return_if_fail

    if obj_type not in obj_table:
        logger.error(f"Invalid object type: {obj_type}")
        return return_if_fail

    query = db.session.query(obj_table[obj_type])

    # CHECK FOR JOINED LOADS

    vuln_joined_loads = []
    host_joined_loads = []

    if pipeline is not None:
        for job in pipeline.jobs:

            if job.model == "host":
                for act in job.actions:
                    if act.field == "hostnames" and act.command == "APPEND":
                        host_joined_loads.append(joinedload(Host.hostnames))

            if job.model == "vulnerability":
                for act in job.actions:
                    if act.target == "asset":
                        if act.field == "hostnames":
                            vuln_joined_loads.append(joinedload(VulnerabilityGeneric.host).subqueryload(Host.hostnames))
                        else:
                            vuln_joined_loads.append(joinedload(VulnerabilityGeneric.host))

    vuln_joined_loads = set(vuln_joined_loads)
    host_joined_loads = set(host_joined_loads)

    filters = []
    if obj_type in ("vulnerability", "vulnerability_web"):
        filters.append(VulnerabilityGeneric.workspace == workspace)
        filters.append(VulnerabilityGeneric.id.in_(obj_ids))
        if vuln_joined_loads:
            query = query.options(*vuln_joined_loads)
    elif obj_type == "host":
        filters.append(Host.workspace == workspace)
        filters.append(Host.id.in_(obj_ids))
        if host_joined_loads:
            query = query.options(*host_joined_loads)
    elif obj_type == "service":
        filters.append(Service.workspace == workspace)
        filters.append(Service.id.in_(obj_ids))

    try:
        objs = query.filter(*filters).all()
    except NoResultFound:
        logger.warning(f"Object not found in db - {obj_type}/{obj_ids} on {workspace}")
        logger.debug(f"obj_type: {obj_type} - id: {obj_ids} - workspace: {workspace}")
        return return_if_fail
    except MultipleResultsFound:
        logger.error("More than one result found")
        logger.debug(f"obj_type: {obj_type} - id: {obj_ids} - workspace: {workspace}")
        return return_if_fail

    return objs, obj_type, workspace, fields, pipeline


def _process_field_data(obj, field):

    field = field.split('/')

    # special case for vulns web that have host field
    if "web" in obj.__class__.__name__.lower() and field[0] == "host":
        field = ["service"] + field

    # special case for service_id
    if field[0] == "service_id":
        return obj, "service_id"

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

    target_obj, field = _process_field_data(obj, condition.field)
    model_data = getattr(target_obj, field, None)

    operator = OPERATORS.get(condition.operator, None)
    if operator is None:
        raise ValueError(f"Operator {condition.operator} not valid")

    class_name = obj.__class__.__name__.lower()
    class_name = "vulnerability" if "web" in class_name else class_name

    data_type = [x.get("type") for x in rules_attributes[class_name] if x.get("name") == condition.field][0]
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
    elif data_type == "null_or_not":
        model_data = None if model_data == [] else model_data
        return operator(model_data)
    elif data_type == "vuln_type":
        vuln_type = "Vulnerability"
        if model_data is not None:
            vuln_type = "Web Vulnerability"
        return operator(vuln_type, data)

    # Fix specific fields
    if field == "hostnames":
        model_data = [x.name for x in model_data]

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


@lru_cache(maxsize=128)
def _get_custom_field_type(cf_name):
    cf = db.session.query(CustomFieldsSchema).filter(CustomFieldsSchema.field_name == cf_name).first()
    if cf is None:
        raise ValueError(f"Custom field \"{cf_name}\" not found in DB")
    return cf.field_type


def _modify_custom_field(cf_name, obj, value, append):

    cf_type = _get_custom_field_type(cf_name)

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


def _create_reference(value, obj):

    create_reference([{"name": value, "type": "other"}], obj.id)
    db.session.add(obj)


def _create_policy_violation(value, obj):

    obj.policy_violations.add(value)
    db.session.add(obj)


def _update_or_append(obj, action, model_to_modify, field_type, can_replace, can_append):

    should_commit = False
    action_to_perform_dict = None

    if field_type == "string":
        if can_append is False or (can_replace is True and action.command == "UPDATE"):
            if action.field == 'severity':
                if obj.severity != action.value:
                    if obj.host_id:
                        host_id = obj.host_id
                    else:
                        host_id = obj.service.host_id
            action_to_perform_dict = {
                "model": model_to_modify,
                "field_type": field_type,
                "field": action.field,
                "value": action.value
            }
        elif can_append is True and action.command == "APPEND":
            current_data = getattr(obj, action.field)
            new_data = current_data + f"\n{action.value}"
            action_to_perform_dict = {
                "model": model_to_modify,
                "field_type": field_type,
                "field": action.field,
                "value": new_data
            }
    elif field_type == "int":
        if can_append is False or (can_replace is True and action.command == "UPDATE"):
            action_to_perform_dict = {
                "model": model_to_modify,
                "field_type": field_type,
                "field": action.field,
                "value": action.value
            }
    elif field_type == "bool":
        if can_append is False or (can_replace is True and action.command == "UPDATE"):
            value = BooleanSchema().load({"value": action.value}).get("value")
            action_to_perform_dict = {
                "model": model_to_modify,
                "field_type": field_type,
                "field": action.field,
                "value": value
            }
    elif field_type == "references":
        _create_reference(action.value, obj)
        should_commit = True
    elif field_type == "policy_violations":
        _create_policy_violation(action.value, obj)
        should_commit = True
    elif field_type == "hostnames":
        current_hostnames = []
        if action.command == "APPEND":
            current_hostnames = [x.name for x in obj.hostnames]
        obj.set_hostnames(current_hostnames + [action.value])
        should_commit = True

    return action_to_perform_dict, should_commit


def _calculate_or_execute_action(objs, action, workflow):
    # This will help to realize if severity was modified or if the vulnerability was deleted for later host stats update
    # Maybe, in the future it will be helpful to return something more useful to know if any field was modified.
    model_to_modify = workflow.model

    all_actions = {}
    host_ids = []
    should_commit = False

    for obj in objs:
        obj_id = obj.id
        host_id = None

        # Check if action.target is set
        # Add more targets here if needed
        if action.target == 'asset':
            if obj.host_id:
                obj_id = host_id = obj.host_id
            else:
                obj_id = host_id = obj.service.host_id
            if obj_id is None:
                raise ValueError(f"Object {obj} has no host_id")
            obj = db.session.query(Host).filter(Host.id == obj_id).first()
            model_to_modify = "host"

        action_to_perform_dict = None

        # Check if custom field
        if action.custom_field is True:
            _modify_custom_field(action.field, obj, action.value, action.command == "APPEND")
            should_commit = True
        else:
            if action.command in ("UPDATE", "APPEND"):

                field_type = fields_lookup[model_to_modify].get(action.field).get("type")
                can_replace = fields_lookup[model_to_modify].get(action.field).get("replace")
                can_append = fields_lookup[model_to_modify].get(action.field).get("append")
                valid_values = fields_lookup[model_to_modify].get(action.field).get("valid", None)

                if (can_append is False and action.command == "APPEND")\
                        or (can_replace is False and action.command == "UPDATE"):
                    raise ValueError(f"Command {action.command} not valid for field {action.field}")

                if valid_values is not None:
                    if action.value not in valid_values:
                        raise ValueError(f"Value {action.value} not in valid values for field {action.field}\n"
                                         f"Valid Values: {valid_values}")

                action_to_perform_dict, should_commit = _update_or_append(obj, action, model_to_modify, field_type,
                                                                          can_replace, can_append)

            if action.command == "DELETE":
                if model_to_modify == 'vulnerability':
                    if obj.host_id:
                        host_id = obj.host_id
                    else:
                        host_id = obj.service.host_id

                action_to_perform_dict = {
                    "model": model_to_modify,
                    "field_type": "DELETE",
                    "field": "DELETE",
                    "value": "DELETE"
                }

        if action_to_perform_dict is not None:
            all_actions.setdefault(frozenset(action_to_perform_dict.items()), []).append(obj_id)
        if host_id is not None:
            host_ids.append(host_id)
    if should_commit:
        # REFERENCES, POLICY VIOLATIONS AND CF ARE COMMITED HERE
        db.session.commit()
    return all_actions, host_ids


def _perform_bulk_actions(actions: dict):
    for action, obj_ids in actions.items():
        action = dict(action)

        if action.get("field_type") == "DELETE":
            model = obj_table[action.get("model")]
            smtp = sqlalchemy.delete(model).where(model.id.in_(obj_ids))
            db.session.execute(smtp)
            db.session.commit()

        else:
            # Create bulk update query
            model = obj_table[action.get("model")]
            field = action.get("field")
            value = action.get("value")
            smtp = sqlalchemy.update(model).where(model.id.in_(obj_ids)).values({field: value})
            db.session.execute(smtp)
            db.session.commit()


def _run_workflow(workflow, objs):
    if workflow.root_condition is None:
        raise ValueError("No root condition, Invalid condition tree")
    logger.debug(f"Running conditions of Workflow id: {workflow.id}, Root condition id: {workflow.root_condition}")
    objs = [obj for obj in objs if _check_condition(obj, workflow.root_condition)]
    if objs:
        logger.debug(f"Conditions passed for Workflow id: {workflow.id}, executing {len(workflow.actions)} actions")
        logger.debug(f"Objects that met conditions: {objs}")
        hosts_to_update = []
        actions_to_perform = {}

        obj_reprs = [repr(obj) for obj in objs]
        message = f"\nJob \"{workflow.name}\" Executed Changes:"
        actions_results = []
        if workflow.actions is not None:
            for action in workflow.actions:
                _actions_to_perform, hosts_to_update = _calculate_or_execute_action(objs, action, workflow)
                actions_results.append(True)
                # merge actions_to_perform with actions
                for act, obj_ids in _actions_to_perform.items():
                    actions_to_perform.setdefault(act, []).extend(obj_ids)

                if action.command == "UPDATE":
                    message += f'\nUpdated field "{action.field}" to "{action.value}"'
                elif action.command == "APPEND":
                    message += f'\nAppended field {action.field}, with "{action.value}"'
                elif action.command == "DELETE":
                    message += f'\nDeleted objects {obj_reprs}'

        # Perform actions
        try:
            if actions_to_perform:
                _perform_bulk_actions(actions_to_perform)
        except IntegrityError as e:
            db.session.rollback()
            logger.error(f"Failed to execute. - {e}")
            actions_results.append(False)
            message += f"\nTask Execution Failed, Error: {e}"
        except Exception as e:
            logger.error(f"Failed to execute. - {e}")
            actions_results.append(False)
            message += f"\nTask Execution Failed, Error: {e}"

        logger.debug(f"Tasks that ran without errors / total = {actions_results.count(True)}/{len(workflow.actions)}")
        message += "\n"
        return True, message, hosts_to_update
    else:
        logger.debug(f"Conditions failed for Workflow id: {workflow.id}, skipping")
        return False, "", None


def _check_workflows(objs, obj_type, ws, fields=None, pipeline=None):
    if False in (objs, obj_type, ws):
        return False, [], None
    if all(isinstance(obj, valid_classes) for obj in objs):

        workflows = pipeline.jobs
        if any(workflows):
            workflows_count = len(workflows)

            logger.info(f"Running pipeline {pipeline} with {workflows_count} job{'s' if workflows_count > 1 else ''}"
                        f" to run with current object {repr(objs)}, IDs: {[x.id for x in workflows]}")
        else:
            logger.debug(f"No workflows found to run with object: {repr(objs)}")
            return True, [], None
        workflows_results = []
        pipeline_wf_order = pipeline.jobs_order
        if pipeline_wf_order == "":
            workflows_ids = [x.id for x in workflows]
        else:
            workflows_ids = pipeline_wf_order.split('-')

        workflows_ids = [int(x) for x in workflows_ids if int(x) in [x.id for x in workflows]]

        logger.debug(f"Executing in order: {workflows_ids}")

        hosts_to_update = []
        for workflow_id in workflows_ids:

            # check each item in objs if its deleted or detached and remove from the list
            objs = [obj for obj in objs if not inspect(obj).deleted and not inspect(obj).detached]
            if not objs:
                logger.debug("Objects deleted by previous workflow, Skipping the rest of the workflows")
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
                result, log, host_to_update = _run_workflow(workflow, objs)
                if host_to_update:
                    hosts_to_update += host_to_update
                workflows_results.append(result)
            except Exception as e:
                workflows_results.append(False)
                logger.error(f"Error while running workflow id [{workflow.id}] - Error: {e}")
                break
        logger.debug(f"Jobs that met conditions and executed actions / Jobs checked total ="
                     f" {workflows_results.count(True)}/{len(workflows)}")

        return True, workflows_results, hosts_to_update
    else:
        logger.debug("Workflows not supported for this type of object")
        return False, [], None


def _change_pipeline_running_status(id, status):
    pipeline = db.session.query(Pipeline).filter(Pipeline.id == id).first()
    if pipeline is None:
        raise ValueError("Invalid Pipeline id")
    pipeline.running = status
    db.session.add(pipeline)
    db.session.commit()


def _process_entry(obj, obj_ids, ws_id, fields=None, run_all=False, pipeline_id=None):
    update_host_stats = []
    if obj and obj_ids and ws_id:
        _, _, host_ids = _check_workflows(*_get_obj_and_workspace(obj, obj_ids, ws_id, fields, pipeline_id))
        return host_ids
    elif run_all is True:
        logger.info(f"Running all objects with pipeline id {pipeline_id}")

        _change_pipeline_running_status(pipeline_id, True)

        try:
            for obj_key, obj_model in run_all_obj_table.items():
                ids = db.session.query(obj_model.id).filter(obj_model.workspace_id == ws_id).all()
                update_host_list = _process_entry(
                    obj_key,
                    ids,
                    ws_id,
                    None,
                    False,
                    pipeline_id if pipeline_id is not None else None
                   )
                if update_host_list:
                    update_host_stats += update_host_list
        except Exception as e:
            logger.error(f"Error while running pipeline\n{e}")
            _change_pipeline_running_status(pipeline_id, False)

        _change_pipeline_running_status(pipeline_id, False)

        logger.debug(f"Hosts to update stats {update_host_stats}")
        return update_host_stats
    return []


workflow_stop_event = Event()


def workflow_background_task(app):
    while not workflow_stop_event.is_set():
        try:
            entry_data = WORKFLOW_QUEUE.get(False, timeout=0.1)
            if entry_data:
                with app.app_context():
                    _process_entry(*entry_data)
        except Empty:
            socketio.sleep(INTERVAL)
        except Exception as ex:
            logger.exception(ex)
    else:
        logger.info("Reports processor stopped")
