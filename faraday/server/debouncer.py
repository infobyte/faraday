# pylint: disable=R1719,C0415
import json
import time
from contextlib import nullcontext
from datetime import datetime

import redis
from sqlalchemy import func, text
from sqlalchemy.sql.functions import coalesce

from faraday.server.config import faraday_server
from faraday.server.models import (
    Host,
    Service,
    VulnerabilityGeneric,
    Workspace,
    db,
)


def _redis_url_from_config() -> str:
    raw = (getattr(faraday_server, "celery_backend_url", None) or "").strip()
    if not raw:
        return "redis://127.0.0.1:6379/0"
    if raw.startswith("redis://") or raw.startswith("rediss://"):
        return raw
    return f"redis://{raw}"


_redis_client = None


def get_redis_client() -> redis.Redis:
    global _redis_client  # pylint: disable=W0603
    if _redis_client is None:
        _redis_client = redis.Redis.from_url(_redis_url_from_config(), decode_responses=True)
    return _redis_client


def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _resolve_workspace_id(parameters: dict) -> int | None:
    """
    Ensure we always debounce by workspace_id.
    - If workspace_id is present, use it.
    - If workspace_name is present, resolve it to workspace_id (DB lookup).
    """
    workspace_id = parameters.get("workspace_id")
    if workspace_id is not None:
        return int(workspace_id)

    workspace_name = parameters.get("workspace_name")
    if not workspace_name:
        return None

    return db.session.query(Workspace.id).filter(Workspace.name == workspace_name).scalar()


def _debounce_key_for_workspace(action_name: str, workspace_id: int) -> str:
    return f"faraday:debounce:{action_name}:ws_id:{workspace_id}"


def _app_ctx(app):
    """Return app context only when not already inside one.

    Prevents Flask-SQLAlchemy from calling db.session.remove() (via teardown)
    when the debounce functions are invoked synchronously within a request.
    """
    from flask import has_app_context  # pylint:disable=import-outside-toplevel
    return nullcontext() if has_app_context() else app.app_context()


#  Update functions
def update_workspace_host_count(workspace_id=None, workspace_name=None):
    from faraday.server.app import get_app, logger  # pylint:disable=import-outside-toplevel
    app = get_app()
    with _app_ctx(app):
        logger.debug(f"Updating workspace: {workspace_id if workspace_id else workspace_name}")
        if not workspace_id and workspace_name:
            workspace_id = db.session.query(Workspace.id).filter(Workspace.name == workspace_name).scalar()
        host_count = db.session.query(func.count(Host.id)).filter(Host.workspace_id == workspace_id).scalar()
        start_time = time.time()
        db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
            {Workspace.host_count: host_count},
            synchronize_session=False
        )
        db.session.commit()
        end_time = time.time()
        logger.debug(f"Query time: {end_time - start_time}")


def update_workspace_service_count(workspace_id=None, workspace_name=None):
    from faraday.server.app import get_app, logger  # pylint:disable=import-outside-toplevel
    app = get_app()
    with _app_ctx(app):
        logger.debug(f"Updating workspace: {workspace_id if workspace_id else workspace_name}")

        # Get workspace_id if it's not provided but workspace_name is provided
        if not workspace_id and workspace_name:
            workspace_id = db.session.query(Workspace.id).filter(Workspace.name == workspace_name).scalar()

        if workspace_id is None:
            logger.warning(f"Workspace with name '{workspace_name}' not found.")
            return

        # Calculate total_service_count
        total_service_count = db.session.query(func.count(Service.id)).filter(
            Service.workspace_id == workspace_id).scalar()

        # Calculate open_service_count
        open_service_count = db.session.query(func.count(Service.id)).filter(Service.workspace_id == workspace_id,
                                                                             Service.status == 'open').scalar()

        # Update the workspace with the new service counts
        db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
            {
                Workspace.total_service_count: total_service_count,
                Workspace.open_service_count: open_service_count
            },
            synchronize_session=False
        )
        db.session.commit()


def update_workspace_vulns_count(workspace_name=None, workspace_id=None):
    from faraday.server.app import get_app, logger
    start_time = datetime.utcnow()

    def count_vulnerabilities(extra_query=None, type_=None, confirmed=None):
        query = db.session.query(func.count(VulnerabilityGeneric.id)).filter(
            VulnerabilityGeneric.workspace_id == workspace_id
        )
        if type_:
            query = query.filter(VulnerabilityGeneric.type == type_)
        if confirmed is not None:
            if db.session.bind.dialect.name == 'sqlite':
                query = query.filter(VulnerabilityGeneric.confirmed == (1 if confirmed else 0))
            elif db.session.bind.dialect.name == 'postgresql':
                query = query.filter(VulnerabilityGeneric.confirmed.is_(True if confirmed else False))
        if extra_query:
            query = query.filter(text(extra_query))
        return query.scalar()

    def count_hosts(workspace_id, confirmed=None, not_closed=None):
        query_vuln_hosts = db.session.query(
            VulnerabilityGeneric.host_id.label('host_id')
        ).filter(
            VulnerabilityGeneric.workspace_id == workspace_id,
            VulnerabilityGeneric.host_id.isnot(None)
        )

        if confirmed is not None:
            if db.session.bind.dialect.name == 'sqlite':
                query_vuln_hosts = query_vuln_hosts.filter(VulnerabilityGeneric.confirmed == (1 if confirmed else 0))
            elif db.session.bind.dialect.name == 'postgresql':
                query_vuln_hosts = query_vuln_hosts.filter(
                    VulnerabilityGeneric.confirmed.is_(True if confirmed else False))

        if not_closed:
            query_vuln_hosts = query_vuln_hosts.filter(VulnerabilityGeneric.status.in_(['open', 're-opened']))

        query_service_hosts = db.session.query(
            Service.host_id.label('host_id')
        ).join(
            VulnerabilityGeneric, VulnerabilityGeneric.service_id == Service.id
        ).filter(
            VulnerabilityGeneric.workspace_id == workspace_id,
            Service.host_id.isnot(None)
        )

        if confirmed is not None:
            if db.session.bind.dialect.name == 'sqlite':
                query_service_hosts = query_service_hosts.filter(
                    VulnerabilityGeneric.confirmed == (1 if confirmed else 0))
            elif db.session.bind.dialect.name == 'postgresql':
                query_service_hosts = query_service_hosts.filter(
                    VulnerabilityGeneric.confirmed.is_(True if confirmed else False))

        if not_closed:
            query_service_hosts = query_service_hosts.filter(VulnerabilityGeneric.status.in_(['open', 're-opened']))

        # Combine both queries
        combined_query = query_vuln_hosts.union_all(query_service_hosts).subquery()

        # Count distinct host_ids
        distinct_hosts_count = db.session.query(func.count(func.distinct(combined_query.c.host_id))).scalar()

        return distinct_hosts_count

    def count_services(workspace_id, confirmed=None, not_closed=None):
        # Define the base query for services
        query_services = db.session.query(func.count(func.distinct(VulnerabilityGeneric.service_id))).filter(
            VulnerabilityGeneric.workspace_id == workspace_id,
            VulnerabilityGeneric.service_id.isnot(None)
        )

        # Apply the filters based on confirmed and not_closed
        if confirmed is not None:
            if db.session.bind.dialect.name == 'sqlite':
                query_services = query_services.filter(VulnerabilityGeneric.confirmed == (1 if confirmed else 0))
            else:
                query_services = query_services.filter(VulnerabilityGeneric.confirmed.is_(True if confirmed else False))

        if not_closed is not None:
            query_services = query_services.filter(VulnerabilityGeneric.status.in_(['open', 're-opened']))

        return query_services.scalar()

    app = get_app()
    with _app_ctx(app):
        if not workspace_id and workspace_name:
            workspace_id = db.session.query(Workspace.id).filter(Workspace.name == workspace_name).scalar()
        logger.debug(f"Calculating ws stats for {workspace_id}")

        start = time.time()

        #  Total Vulnerabilities By Type

        vulnerability_web_count = count_vulnerabilities(type_='vulnerability_web')
        vulnerability_standard_count = count_vulnerabilities(type_='vulnerability')
        vulnerability_code_count = count_vulnerabilities(type_='vulnerability_code')

        #  Total Vulnerabilities by dashboard filters

        vulnerability_total_count = count_vulnerabilities()
        vulnerability_confirmed_count = count_vulnerabilities(confirmed=True)
        vulnerability_notclosed_count = count_vulnerabilities(extra_query="status IN ('open', 're-opened')")
        vulnerability_notclosed_confirmed_count = count_vulnerabilities(extra_query="status IN ('open', 're-opened')",
                                                                                    confirmed=True)

        #  Total Vulnerabilities by status

        vulnerability_closed_count = count_vulnerabilities(extra_query="status IN ('closed', 'risk-accepted')")
        vulnerability_open_count = count_vulnerabilities(extra_query="status IN ('open', 're-opened')")
        vulnerability_re_opened_count = count_vulnerabilities(extra_query="status = 're-opened'")
        vulnerability_risk_accepted_count = count_vulnerabilities(extra_query="status = 'risk-accepted'")

        #  Vulnerabilities by Status - Confirmed

        vulnerability_open_confirmed_count = count_vulnerabilities(extra_query="status IN ('open', 're-opened')", confirmed=True)
        vulnerability_closed_confirmed_count = count_vulnerabilities(extra_query="status IN ('closed', 'risk-accepted')", confirmed=True)
        vulnerability_re_opened_confirmed_count = count_vulnerabilities(extra_query="status = 're-opened'", confirmed=True)
        vulnerability_risk_accepted_confirmed_count = count_vulnerabilities(extra_query="status = 'risk-accepted'", confirmed=True)

        #  Not closed by type

        vulnerability_web_notclosed_count = count_vulnerabilities(type_='vulnerability_web',
                                                                  extra_query="status IN ('open', 're-opened')")
        vulnerability_code_notclosed_count = count_vulnerabilities(type_='vulnerability_code',
                                                                   extra_query="status IN ('open', 're-opened')")
        vulnerability_standard_notclosed_count = count_vulnerabilities(type_='vulnerability',
                                                                       extra_query="status IN ('open', 're-opened')")
        #  Confirmed by type

        vulnerability_web_confirmed_count = count_vulnerabilities(type_='vulnerability_web', confirmed=True)
        vulnerability_code_confirmed_count = count_vulnerabilities(type_='vulnerability_code', confirmed=True)
        vulnerability_standard_confirmed_count = count_vulnerabilities(type_='vulnerability', confirmed=True)

        #  Confirmed and not closed by type

        vulnerability_web_notclosed_confirmed_count = count_vulnerabilities(type_='vulnerability_web', confirmed=True,
                                                                            extra_query="status IN ('open', 're-opened')")
        vulnerability_code_notclosed_confirmed_count = count_vulnerabilities(type_='vulnerability_code', confirmed=True,
                                                                             extra_query="status IN ('open', 're-opened')")
        vulnerability_standard_notclosed_confirmed_count = count_vulnerabilities(type_='vulnerability', confirmed=True,
                                                                                 extra_query="status IN ('open', 're-opened')")

        #  Not Closed by severity

        vulnerability_high_notclosed_count = count_vulnerabilities(extra_query="severity = 'high' AND status IN ('open', 're-opened')")
        vulnerability_critical_notclosed_count = count_vulnerabilities(extra_query="severity = 'critical' AND status IN ('open', 're-opened')")
        vulnerability_medium_notclosed_count = count_vulnerabilities(extra_query="severity = 'medium' AND status IN ('open', 're-opened')")
        vulnerability_low_notclosed_count = count_vulnerabilities(extra_query="severity = 'low' AND status IN ('open', 're-opened')")
        vulnerability_informational_notclosed_count = count_vulnerabilities(extra_query="severity = 'informational' AND status IN ('open', 're-opened')")
        vulnerability_unclassified_notclosed_count = count_vulnerabilities(extra_query="severity = 'unclassified' AND status IN ('open', 're-opened')")

        # Confirmed by severity

        vulnerability_high_confirmed_count = count_vulnerabilities(extra_query="severity = 'high'", confirmed=True)
        vulnerability_critical_confirmed_count = count_vulnerabilities(extra_query="severity = 'critical'", confirmed=True)
        vulnerability_medium_confirmed_count = count_vulnerabilities(extra_query="severity = 'medium'", confirmed=True)
        vulnerability_low_confirmed_count = count_vulnerabilities(extra_query="severity = 'low'", confirmed=True)
        vulnerability_informational_confirmed_count = count_vulnerabilities(extra_query="severity = 'informational'", confirmed=True)
        vulnerability_unclassified_confirmed_count = count_vulnerabilities(extra_query="severity = 'unclassified'", confirmed=True)

        #  Not closed and confirmed by severity

        vulnerability_high_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'high' AND status IN ('open', 're-opened')", confirmed=True)
        vulnerability_critical_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'critical' AND status IN ('open', 're-opened')", confirmed=True)
        vulnerability_medium_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'medium' AND status IN ('open', 're-opened')", confirmed=True)
        vulnerability_low_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'low' AND status IN ('open', 're-opened')", confirmed=True)
        vulnerability_informational_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'informational' AND status IN ('open', 're-opened')", confirmed=True)
        vulnerability_unclassified_notclosed_confirmed_count = count_vulnerabilities(
            extra_query="severity = 'unclassified' AND status IN ('open', 're-opened')", confirmed=True)

        #  Count hosts and services for not closed vulnerabilities

        host_notclosed_count = count_hosts(workspace_id, not_closed=True)
        service_notclosed_count = count_services(workspace_id, not_closed=True)

        #  Count hosts and services for confirmed vulnerabilities

        host_confirmed_count = count_hosts(workspace_id, confirmed=True)
        service_confirmed_count = count_services(workspace_id, confirmed=True)

        #  Count hosts and services for confirmed and not closed vulnerabilities

        host_notclosed_confirmed_count = count_hosts(workspace_id, confirmed=True, not_closed=True)
        service_notclosed_confirmed_count = count_services(workspace_id, confirmed=True, not_closed=True)

        end = time.time()

        logger.debug(f"Count execution time in update workspace vulns count = {end - start}")
        logger.debug(f"Vulnerability closed count: {vulnerability_closed_count} ")

        db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
            {
                Workspace.vulnerability_web_count: vulnerability_web_count,
                Workspace.vulnerability_standard_count: vulnerability_standard_count,
                Workspace.vulnerability_code_count: vulnerability_code_count,
                Workspace.vulnerability_total_count: vulnerability_total_count,
                Workspace.vulnerability_confirmed_count: vulnerability_confirmed_count,
                Workspace.vulnerability_notclosed_count: vulnerability_notclosed_count,
                Workspace.vulnerability_notclosed_confirmed_count: vulnerability_notclosed_confirmed_count,
                Workspace.vulnerability_closed_count: vulnerability_closed_count,
                Workspace.vulnerability_open_count: vulnerability_open_count,
                Workspace.vulnerability_re_opened_count: vulnerability_re_opened_count,
                Workspace.vulnerability_risk_accepted_count: vulnerability_risk_accepted_count,
                Workspace.vulnerability_open_confirmed_count: vulnerability_open_confirmed_count,
                Workspace.vulnerability_closed_confirmed_count: vulnerability_closed_confirmed_count,
                Workspace.vulnerability_re_opened_confirmed_count: vulnerability_re_opened_confirmed_count,
                Workspace.vulnerability_risk_accepted_confirmed_count: vulnerability_risk_accepted_confirmed_count,
                Workspace.vulnerability_web_notclosed_count: vulnerability_web_notclosed_count,
                Workspace.vulnerability_code_notclosed_count: vulnerability_code_notclosed_count,
                Workspace.vulnerability_standard_notclosed_count: vulnerability_standard_notclosed_count,
                Workspace.vulnerability_web_confirmed_count: vulnerability_web_confirmed_count,
                Workspace.vulnerability_code_confirmed_count: vulnerability_code_confirmed_count,
                Workspace.vulnerability_standard_confirmed_count: vulnerability_standard_confirmed_count,
                Workspace.vulnerability_web_notclosed_confirmed_count: vulnerability_web_notclosed_confirmed_count,
                Workspace.vulnerability_code_notclosed_confirmed_count: vulnerability_code_notclosed_confirmed_count,
                Workspace.vulnerability_standard_notclosed_confirmed_count: vulnerability_standard_notclosed_confirmed_count,
                Workspace.vulnerability_high_notclosed_count: vulnerability_high_notclosed_count,
                Workspace.vulnerability_critical_notclosed_count: vulnerability_critical_notclosed_count,
                Workspace.vulnerability_medium_notclosed_count: vulnerability_medium_notclosed_count,
                Workspace.vulnerability_low_notclosed_count: vulnerability_low_notclosed_count,
                Workspace.vulnerability_informational_notclosed_count: vulnerability_informational_notclosed_count,
                Workspace.vulnerability_unclassified_notclosed_count: vulnerability_unclassified_notclosed_count,
                Workspace.vulnerability_high_confirmed_count: vulnerability_high_confirmed_count,
                Workspace.vulnerability_critical_confirmed_count: vulnerability_critical_confirmed_count,
                Workspace.vulnerability_medium_confirmed_count: vulnerability_medium_confirmed_count,
                Workspace.vulnerability_low_confirmed_count: vulnerability_low_confirmed_count,
                Workspace.vulnerability_informational_confirmed_count: vulnerability_informational_confirmed_count,
                Workspace.vulnerability_unclassified_confirmed_count: vulnerability_unclassified_confirmed_count,
                Workspace.vulnerability_high_notclosed_confirmed_count: vulnerability_high_notclosed_confirmed_count,
                Workspace.vulnerability_critical_notclosed_confirmed_count: vulnerability_critical_notclosed_confirmed_count,
                Workspace.vulnerability_medium_notclosed_confirmed_count: vulnerability_medium_notclosed_confirmed_count,
                Workspace.vulnerability_low_notclosed_confirmed_count: vulnerability_low_notclosed_confirmed_count,
                Workspace.vulnerability_informational_notclosed_confirmed_count: vulnerability_informational_notclosed_confirmed_count,
                Workspace.vulnerability_unclassified_notclosed_confirmed_count: vulnerability_unclassified_notclosed_confirmed_count,
                Workspace.host_notclosed_count: host_notclosed_count,
                Workspace.service_notclosed_count: service_notclosed_count,
                Workspace.host_confirmed_count: host_confirmed_count,
                Workspace.service_confirmed_count: service_confirmed_count,
                Workspace.host_notclosed_confirmed_count: host_notclosed_confirmed_count,
                Workspace.service_notclosed_confirmed_count: service_notclosed_confirmed_count
            },
            synchronize_session=False
        )

        #  Total By Severity

        vuln_counts = (
            db.session.query(
                coalesce(func.sum(Host.vulnerability_critical_generic_count), 0).label('total_critical'),
                coalesce(func.sum(Host.vulnerability_high_generic_count), 0).label('total_high'),
                coalesce(func.sum(Host.vulnerability_medium_generic_count), 0).label('total_medium'),
                coalesce(func.sum(Host.vulnerability_low_generic_count), 0).label('total_low'),
                coalesce(func.sum(Host.vulnerability_info_generic_count), 0).label('total_info'),
                coalesce(func.sum(Host.vulnerability_unclassified_generic_count), 0).label('total_unclassified'),
                coalesce(
                    func.sum(
                        Host.vulnerability_critical_generic_count
                        + Host.vulnerability_high_generic_count
                        + Host.vulnerability_medium_generic_count
                        + Host.vulnerability_low_generic_count
                        + Host.vulnerability_info_generic_count
                        + Host.vulnerability_unclassified_generic_count
                    ),
                    0
                ).label('total_vulnerabilities')
            )
            .filter(Host.workspace_id == workspace_id)
            .first()
        )

        # Update the Workspace fields with the calculated sums
        db.session.query(Workspace).filter(Workspace.id == workspace_id).update({
            Workspace.vulnerability_critical_count: vuln_counts.total_critical,
            Workspace.vulnerability_high_count: vuln_counts.total_high,
            Workspace.vulnerability_medium_count: vuln_counts.total_medium,
            Workspace.vulnerability_low_count: vuln_counts.total_low,
            Workspace.vulnerability_informational_count: vuln_counts.total_info,
            Workspace.vulnerability_unclassified_count: vuln_counts.total_unclassified,
            Workspace.vulnerability_total_count: vuln_counts.total_vulnerabilities
        }, synchronize_session='fetch')

        db.session.commit()
    end_time = datetime.utcnow()
    logger.info(f"workspace vulns count took {end_time - start_time}")


def update_workspace_update_date(workspace_dates_dict):
    from faraday.server.app import get_app  # pylint:disable=import-outside-toplevel
    app = get_app()
    with _app_ctx(app):
        for workspace_id, update_date in workspace_dates_dict.items():
            db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
                {Workspace.update_date: update_date},
                synchronize_session=False
            )
        db.session.commit()



#  Debounce functions


def debounce_workspace_update(workspace_name, debouncer=None, update_date=None, workspace_id=None):
    """
    Debounce workspace update_date by workspace_id.
    """
    from faraday.server.app import get_debouncer, logger  # pylint:disable=import-outside-toplevel
    if not debouncer:
        debouncer = get_debouncer()
    if not update_date:
        update_date = datetime.utcnow()

    if workspace_id is None:
        workspace_id = db.session.query(Workspace.id).filter(Workspace.name == workspace_name).scalar()
    if workspace_id is None:
        logger.warning(f"Debounce: workspace not found while resolving id (workspace_name={workspace_name})")
        return debouncer

    debouncer.debounce(update_workspace_update_date, {"workspace_id": int(workspace_id), "update_date": update_date})
    return debouncer


def debounce_workspace_host_count(workspace_id=None, workspace_name=None, debouncer=None):
    from faraday.server.app import get_debouncer
    if not debouncer:
        debouncer = get_debouncer()
    if workspace_id:
        debouncer.debounce(update_workspace_host_count, {'workspace_id': workspace_id})
    elif workspace_name:
        debouncer.debounce(update_workspace_host_count, {'workspace_name': workspace_name})
    return debouncer


def debounce_workspace_service_count(workspace_id=None, workspace_name=None, debouncer=None):
    from faraday.server.app import get_debouncer
    if not debouncer:
        debouncer = get_debouncer()
    if workspace_id:
        debouncer.debounce(update_workspace_service_count, {'workspace_id': workspace_id})
    elif workspace_name:
        debouncer.debounce(update_workspace_service_count, {'workspace_name': workspace_name})
    return debouncer


def debounce_workspace_vulns_count_update(workspace_id=None, workspace_name=None, debouncer=None):
    from faraday.server.app import get_debouncer
    if not debouncer:
        debouncer = get_debouncer()
    if workspace_id:
        debouncer.debounce(update_workspace_vulns_count, {'workspace_id': workspace_id})
    elif workspace_name:
        debouncer.debounce(update_workspace_vulns_count, {'workspace_name': workspace_name})
    return debouncer


class Debouncer:
    """
    Distributed debouncer (Redis + Celery), no threads:
    - Stores the latest payload in Redis (per action + workspace)
    - Increments token
    - Enqueues a Celery task (in tasks.py) with countdown=wait
    - The task executes only if the token matches (otherwise, it is discarded)
    """

    def __init__(self, wait=10):
        self.wait = wait
        self._redis = get_redis_client()

    def debounce(self, action, parameters):
        from faraday.server.app import logger  # pylint:disable=import-outside-toplevel
        from faraday.server.tasks import execute_debounced_action  # pylint:disable=import-outside-toplevel

        action_name = getattr(action, "__name__", None)
        if not action_name:
            return

        parameters = parameters or {}

        workspace_id = _resolve_workspace_id(parameters)
        if workspace_id is None:
            logger.warning(
                f"Debouncer(redis): missing workspace identifier (action={action_name} "
                f"parameters={list(parameters.keys())})"
            )
            return

        debounce_key = _debounce_key_for_workspace(action_name, workspace_id)

        token_key = f"{debounce_key}:token"
        meta_key = f"{debounce_key}:meta"
        payload_key = f"{debounce_key}:payload"

        if not faraday_server.celery_enabled:
            logger.debug(f"Debouncer(redis): celery disabled, executing sync action={action_name} key={debounce_key}")
            if action == update_workspace_update_date:
                update_workspace_update_date({parameters["workspace_id"]: parameters.get("update_date") or datetime.utcnow()})
            else:
                action(**parameters)
            return

        meta = {"action": action_name}
        payload = {"parameters": parameters}

        self._redis.hset(meta_key, mapping=meta)
        self._redis.set(payload_key, json.dumps(payload, sort_keys=True, default=_json_default))

        existing_token = self._redis.get(token_key)
        token = int(self._redis.incr(token_key))

        time_to_live = max(int(self.wait) + 120, 180)
        self._redis.expire(token_key, time_to_live)
        self._redis.expire(meta_key, time_to_live)
        self._redis.expire(payload_key, time_to_live)

        if existing_token:
            logger.info(
                f"Debouncer(redis): postponed (action={action_name} key={debounce_key} old_token={existing_token} "
                f"new_token={token} countdown={self.wait}s)"
            )
        else:
            logger.info(
                f"Debouncer(redis): scheduled (action={action_name} key={debounce_key} token={token} "
                f"wait={self.wait}s)"
            )
        execute_debounced_action.apply_async(args=[debounce_key, token], countdown=self.wait)

