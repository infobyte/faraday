# pylint: disable=R1719,C0415
import time
from threading import Timer
from datetime import datetime
from sqlalchemy import func, text
from sqlalchemy.sql.functions import coalesce
from faraday.server.models import db, Workspace, Host, Service, VulnerabilityGeneric


#  Update functions
def update_workspace_host_count(workspace_id=None, workspace_name=None):
    from faraday.server.app import get_app, logger  # pylint:disable=import-outside-toplevel
    app = get_app()
    with app.app_context():
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
    with app.app_context():
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
    with app.app_context():
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
    with app.app_context():
        for workspace_id, update_date in workspace_dates_dict.items():
            db.session.query(Workspace).filter(Workspace.id == workspace_id).update(
                {Workspace.update_date: update_date},
                synchronize_session=False
            )
        db.session.commit()


def update_workspace_update_date_with_name(workspace_dates_dict):
    from faraday.server.app import get_app, logger  # pylint:disable=import-outside-toplevel
    app = get_app()
    with app.app_context():
        sorted_workspaces = sorted(workspace_dates_dict.items(), key=lambda item: item[1])  # Preserve execution order
        for workspace_name, update_date in sorted_workspaces:
            logger.debug(f"Updating workspace: {workspace_name}")
            db.session.query(Workspace).filter(Workspace.name == workspace_name).update(
                {Workspace.update_date: update_date},
                synchronize_session=False
                )
            db.session.commit()

#  Debounce functions


def debounce_workspace_update(workspace_name, debouncer=None, update_date=None):
    from faraday.server.app import get_debouncer  # pylint:disable=import-outside-toplevel
    if not debouncer:
        debouncer = get_debouncer()
    if not update_date:
        update_date = datetime.utcnow()
    debouncer.debounce(update_workspace_update_date_with_name,
                       {'workspace_name': workspace_name, 'update_date': update_date})
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

    Debouncer class recieves functions (with their parameters) and delays the execution of those functions using one Timer thread.
    The function is saved in a set, so if the same function is received with the same parameters within the execution wait time,
    it will not be added to the set, and it will reset the wait time.

    Something to improve: Currently it resolves the logic for updating workspace update_date using a dictionary that saves the
    workspace_id and the last update_date for that workspace. This could resolve other update issues for other tables, adding
    another dictionary for that table with the same structure.

    """

    def __init__(self, wait=10):
        self.wait = wait
        self.timer = None
        self.actions = set()  # Dic structure: {'action':function, 'parameters': {'param1':1, 'param2':b}}
        self.update_dates = {"workspaces": {}}

    def debounce(self, action, parameters):

        """Recieves a function and a dict with its parameters, and saves them in a set.
        The dict is converted to tuple to ensure that the set overrides duplicated functions.
        As updates dates will always be different, it saves the workspaces and their update dates
        in a dict, so if the same workspace calls the update function, the previous update date will
        be overwritten. Then it uses a timer to execute the functions saved in the set."""
        if action == update_workspace_update_date_with_name:
            self.update_dates['workspaces'][parameters['workspace_name']] = parameters['update_date']
            self.actions.add(tuple({'action': action}.items()))
        else:
            self.actions.add(tuple({'action': action, 'parameters': tuple(parameters.items())}.items()))
        if self.timer:
            self.timer.cancel()

        self.timer = Timer(self.wait, self._debounced_actions)
        self.timer.start()

    def _debounced_actions(self):
        for item in self.actions:
            item = dict(item)
            action = item['action']
            if action == update_workspace_update_date_with_name:
                action(self.update_dates['workspaces'])
            else:
                parameters = dict(item['parameters'])
                action(**parameters)
        self.actions = set()
        self.update_dates = {"workspaces": {}}
