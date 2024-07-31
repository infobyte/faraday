import time
from datetime import datetime
from typing import Optional, List

from celery import group, chord
from celery.utils.log import get_task_logger
from sqlalchemy import (
    func,
    or_,
    and_,
)

from faraday.server.config import faraday_server
from faraday.server.extensions import celery
from faraday.server.models import (
    db,
    Workspace,
    Command,
    Service,
    Host,
    VulnerabilityGeneric,
    VulnerabilityWeb,
    Vulnerability,
)
from faraday.server.utils.workflows import _process_entry
from faraday.server.debouncer import debounce_workspace_update

logger = get_task_logger(__name__)


@celery.task
def on_success_process_report_task(results, command_id=None):
    command_end_date = datetime.utcnow()
    start_time = time.time()
    command = db.session.query(Command).filter(Command.id == command_id).first()
    if not command:
        logger.error("File imported but command id %s was not found", command_id)
        return
    else:
        workspace = db.session.query(Workspace).filter(Workspace.id == command.workspace_id).first()
        if workspace.name:
            debounce_workspace_update(workspace.name)
    logger.debug(f"Fetching command took {time.time() - start_time}")
    command.end_date = command_end_date
    logger.error("File for command id %s successfully imported", command_id)
    db.session.commit()

    # Apply Workflow
    pipeline = [pipeline for pipeline in command.workspace.pipelines if pipeline.enabled]
    if pipeline:
        vuln_object_ids = [command_object.object_id for command_object in command.command_objects if command_object.object_type == "vulnerability"]
        vuln_web_object_ids = [command_object.object_id for command_object in command.command_objects if command_object.object_type == "vulnerability_web"]
        host_object_ids = [command_object.object_id for command_object in command.command_objects if command_object.object_type == "host"]

        # Process vulns
        if vuln_object_ids:
            workflow_task.delay("vulnerability", vuln_object_ids, command.workspace.id, update_hosts=False)

        # Process vulns web
        if vuln_web_object_ids:
            workflow_task.delay("vulnerability_web", vuln_web_object_ids, command.workspace.id, update_hosts=False)

        # Process hosts
        if host_object_ids:
            workflow_task.delay("host", host_object_ids, command.workspace.id, update_hosts=False)

    logger.debug("No pipelines found in ws %s", command.workspace.name)

    for result in results:
        if result['created']:
            calc_vulnerability_stats.delay(result['host_id'])


@celery.task()
def on_chord_error(request, exc, *args, **kwargs):
    command_id = kwargs.get("command_id", None)
    if command_id:
        logger.error("File for command id %s imported with errors", command_id)
        command = db.session.query(Command).filter(Command.id == command_id).first()
        command.end_date = datetime.utcnow()
        db.session.commit()
    logger.error(f'Task {request.id} raised error: {exc}')


@celery.task(acks_late=True)
def process_report_task(workspace_id: int, command: dict, hosts):
    callback = on_success_process_report_task.subtask(kwargs={'command_id': command['id']}).on_error(on_chord_error.subtask(kwargs={'command_id': command['id']}))
    g = [create_host_task.s(workspace_id, command, host) for host in hosts]
    logger.info("Task to execute %s", len(g))
    group_of_tasks = group(g)
    ret = chord(group_of_tasks)(callback)

    return ret


@celery.task()
def workflow_task(obj_type: str, obj_ids: list, workspace_id: int, fields=None, run_all=False, pipeline_id=None, update_hosts=False):
    hosts_to_update = _process_entry(obj_type, obj_ids, workspace_id, fields=fields, run_all=run_all, pipeline_id=pipeline_id)
    if hosts_to_update:
        logger.debug("Updating hosts stats from workflow task...")
        update_host_stats.delay(hosts_to_update, [])


@celery.task(ignore_result=False, acks_late=True)
def create_host_task(workspace_id, command: dict, host):
    from faraday.server.api.modules.bulk_create import _create_host  # pylint: disable=import-outside-toplevel
    created_objects = {}
    db.engine.dispose()
    start_time = time.time()
    workspace = Workspace.query.filter_by(id=workspace_id).first()
    if not workspace:
        logger.error("Workspace %s not found", workspace_id)
        return created_objects
    logger.debug(f"Fetching ws took {time.time() - start_time}")
    try:
        logger.debug(f"Processing host {host['ip']}")
        created_objects = _create_host(workspace, host, command)
    except Exception as e:
        logger.error("Could not create host %s", e)
        # TODO: update command warnings with host failed/errors
        return created_objects
    logger.info(f"Created {created_objects}")
    # TODO: Instead of created objects, return warnings/errors/created associated to host
    # {'host_ip_1', 'created', 'host_ip_2': 'Failed with bla'}
    return created_objects


@celery.task(ignore_result=False)
def pre_process_report_task(workspace_name: str, command_id: int, file_path: str,
                            plugin_id: Optional[int], user_id: Optional[int], ignore_info: bool,
                            dns_resolution: bool, vuln_tag: Optional[list] = None,
                            host_tag: Optional[list] = None, service_tag: Optional[list] = None):
    from faraday.server.utils.reports_processor import process_report  # pylint: disable=import-outside-toplevel
    from faraday_plugins.plugins.manager import PluginsManager, ReportAnalyzer  # pylint: disable=import-outside-toplevel
    from faraday.settings.reports import ReportsSettings  # pylint: disable=import-outside-toplevel

    if not plugin_id:
        start_time = time.time()
        plugins_manager = PluginsManager(ReportsSettings.settings.custom_plugins_folder)
        report_analyzer = ReportAnalyzer(plugins_manager)
        plugin = report_analyzer.get_plugin(file_path)

        if not plugin:
            from faraday.server.utils.reports_processor import command_status_error  # pylint: disable=import-outside-toplevel
            logger.info("Could not get plugin for file")
            logger.info("Plugin analyzer took %s", time.time() - start_time)
            command_status_error(command_id)
            return

        logger.info(
            f"Plugin for file: {file_path} Plugin: {plugin.id}"
        )
        plugin_id = plugin.id
        logger.info("Plugin analyzer took %s", time.time() - start_time)

    process_report(
        workspace_name,
        command_id,
        file_path,
        plugin_id,
        user_id,
        ignore_info,
        dns_resolution,
        vuln_tag,
        host_tag,
        service_tag
    )


@celery.task()
def update_host_stats(hosts: List, services: List) -> None:
    all_hosts = set(hosts)
    services_host_id = db.session.query(Service.host_id).filter(Service.id.in_(services)).all()
    for host_id in services_host_id:
        all_hosts.add(host_id[0])
    for host in all_hosts:
        # stat calc
        if faraday_server.celery_enabled:
            calc_vulnerability_stats.delay(host)
        else:
            calc_vulnerability_stats(host)


@celery.task()
def calc_vulnerability_stats(host_id: int) -> None:
    logger.debug(f"Calculating vulns stats for host {host_id}")
    severity_model_names = {
        'critical': 'vulnerability_critical_generic_count',
        'high': 'vulnerability_high_generic_count',
        'medium': 'vulnerability_medium_generic_count',
        'informational': 'vulnerability_info_generic_count',
        'low': 'vulnerability_low_generic_count',
        'unclassified': 'vulnerability_unclassified_generic_count',
    }
    severities_dict = {
        'vulnerability_critical_generic_count': 0,
        'vulnerability_high_generic_count': 0,
        'vulnerability_medium_generic_count': 0,
        'vulnerability_low_generic_count': 0,
        'vulnerability_info_generic_count': 0,
        'vulnerability_unclassified_generic_count': 0,
    }
    severities = db.session.query(func.count(VulnerabilityGeneric.severity), VulnerabilityGeneric.severity)\
        .join(Service, Service.id.in_([Vulnerability.service_id, VulnerabilityWeb.service_id]), isouter=True)\
        .join(Host, or_(Host.id == VulnerabilityGeneric.host_id, Host.id == Service.host_id))\
        .filter(or_(VulnerabilityGeneric.host_id == host_id,
                    and_(VulnerabilityGeneric.service_id == Service.id,
                         Service.host_id == host_id
                         )
                    )
                )\
        .group_by(VulnerabilityGeneric.severity).all()

    for severity in severities:
        severities_dict[severity_model_names[severity[1]]] = severity[0]

    logger.debug(f"Host vulns stats {severities_dict}")

    db.session.query(Host).filter(Host.id == host_id).update(severities_dict)
    db.session.commit()
