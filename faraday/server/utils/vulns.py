import re
import logging
import json

from sqlalchemy.exc import IntegrityError
from sqlalchemy.inspection import inspect
from sqlalchemy import func, update

from faraday.server.models import (
    CVE,
    db,
    Reference,
    PolicyViolation,
    OWASP,
    VulnerabilityGeneric
)
from faraday.server.utils.database import is_unique_constraint_violation
from faraday.server.utils.reference import create_reference
from flask import jsonify

logger = logging.getLogger(__name__)

# Meta fields in common for VulnerabilitySchema, VulnerabilityWebSchema and VulnerabilityFilterSet
BASE_FIELDS = (
    "command_id",
    "confirmed",
    "data",
    "description",
    "id",
    "name",
    "resolution",
    "service",
    "severity",
    "status",
    "target",
    "tool",
)

# Meta fields in common for VulnerabilityWebSchema and VulnerabilityFilterSet
WEB_BASE_FIELDS = (
    "method",
    "path",
    "request",
    "response",
    "status_code",
    "website",
)

# Meta fields in common for VulnerabilitySchema and VulnerabilityWebSchema
SCHEMA_FIELDS = BASE_FIELDS + (
    "_attachments",
    "_id",
    "_rev",
    "custom_fields",
    "cve",
    "cvss2",
    "cvss3",
    "cvss4",
    "cwe",
    "date",
    "desc",
    "easeofresolution",
    "external_id",
    "host_os",
    "hostnames",
    "impact",
    "issuetracker",
    "metadata",
    "obj_id",
    "owned",
    "owner",
    "parent",
    "parent_type",
    "policyviolations",
    "refs",
    "risk",
    "tags",
    "type",
    "workspace_name",
)

# Meta fields exclusive for VulnerabilityWebSchema
WEB_SCHEMA_FIELDS = SCHEMA_FIELDS + WEB_BASE_FIELDS + (
    "owasp",
    "params",
    "pname",
    "query",
)

# Meta fields exclusive for VulnerabilityFilterSet
FILTER_SET_FIELDS = BASE_FIELDS + WEB_BASE_FIELDS + (
    "creator",
    "ease_of_resolution",
    "parameter_name",
    "parameters",
    "query_string",
    "service_id",
)

FILTER_SET_STRICT_FIELDS = (
    "confirmed",
    "ease_of_resolution",
    "method",
    "service_id",
    "severity",
    "status",
    "workspace.name",
)

WORKSPACED_SCHEMA_EXCLUDE_FIELDS = ("workspace.name",)


def parse_cve_references_and_policyviolations(vuln, references, policyviolations, cve_list):
    vuln.refs = create_reference(references, vuln.id)
    add_policy_violations(vuln, policyviolations)

    parsed_cve_list = []
    for cve in cve_list:
        parsed_cve_list += re.findall(CVE.CVE_PATTERN, cve.upper())

    add_cves(vuln, parsed_cve_list)

    return vuln


def get_or_create_owasp(owasp_name: str) -> [None, OWASP]:
    if not owasp_name:
        logger.error("owasp_name not provided.")
        return None
    owasp = OWASP.query.filter(OWASP.name == owasp_name).first()
    if not owasp:
        try:
            owasp = OWASP(name=owasp_name)
            db.session.add(owasp)
            db.session.commit()
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                logger.error("Could not create owasp %s", owasp_name)
                return None
            logger.debug("OWASP violated unique constraint. Rollback in progress")
            db.session.rollback()
            owasp = OWASP.query.filter(OWASP.name == owasp_name).first()
            if not owasp:
                logger.error("Could not create owasp")
                return None
            logger.debug("OWASP object finally obtained")
    return owasp


def get_or_create_reference(reference_name: str, reference_type: str, workspace_id: int) -> [None, Reference]:
    logger.debug("Trying to create reference %s with type %s fow ws %s",
                 reference_name,
                 reference_type,
                 workspace_id)
    if not reference_name or not workspace_id:
        logger.error("Reference or workspace not provided.")
        return None
    try:
        reference_obj = Reference(name=reference_name, type=reference_type, workspace_id=workspace_id)
        db.session.add(reference_obj)
        db.session.commit()
    except IntegrityError as ex:
        if not is_unique_constraint_violation(ex):
            logger.exception("Could not create reference %s with type %s fow ws %s", reference_name,
                             reference_type,
                             workspace_id,
                             exc_info=ex)
            return None
        logger.debug("Reference violated unique constraint. Rollback in progress")
        db.session.rollback()
        reference_obj = Reference.query.filter(Reference.name == reference_name,
                                               Reference.type == reference_type,
                                               Reference.workspace_id == workspace_id).first()
        if not reference_obj:
            logger.error("Could not get reference")
            return None
        logger.debug("Reference object finally obtained")
    return reference_obj


def add_cves(obj, cves):
    for cve_name in cves:
        cve = CVE.query.filter(CVE.name == cve_name).first()
        if not cve:
            try:
                cve = CVE(name=cve_name)
                db.session.add(cve)
                db.session.commit()
            except IntegrityError as ex:
                if not is_unique_constraint_violation(ex):
                    logger.error("Could not create cve %s", cve_name)
                    logger.exception(ex)
                    continue
                logger.debug("CVE violated unique constraint. Rollback in progress")
                db.session.rollback()
                cve = CVE.query.filter_by(name=cve_name).first()
                if not cve:
                    logger.error("Could not get cve")
                    continue
                logger.debug("CVE object finally obtained")
        obj.cve_instances.add(cve)


def create_cve_obj(cve_name):
    cve = CVE.query.filter(CVE.name == cve_name).first()
    if not cve:
        try:
            cve = CVE(name=cve_name)
            db.session.add(cve)
            db.session.commit()
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                logger.error("Could not create cve %s", cve_name)
                logger.exception(ex)
                return None
            logger.debug("CVE violated unique constraint. Rollback in progress")
            db.session.rollback()
            cve = CVE.query.filter_by(name=cve_name).first()
            if not cve:
                logger.error("Could not get cve")
                return None
            logger.debug("CVE object finally obtained")
    return cve


def create_cves_append(cves):
    cve_obj_list = []
    for cve_name in cves:
        cve = CVE.query.filter(CVE.name == cve_name).first()
        if not cve:
            try:
                cve = CVE(name=cve_name)
                db.session.add(cve)
                db.session.commit()
            except IntegrityError as ex:
                if not is_unique_constraint_violation(ex):
                    logger.error("Could not create cve %s", cve_name)
                    logger.exception(ex)
                    continue
                logger.debug("CVE violated unique constraint. Rollback in progress")
                db.session.rollback()
                cve = CVE.query.filter_by(name=cve_name).first()
                if not cve:
                    logger.error("Could not get cve")
                    continue
                logger.debug("CVE object finally obtained")
        cve_obj_list.append(cve)
    return cve_obj_list


def add_references(obj, references):
    for reference_dict in references:
        reference_name = reference_dict.get('name')
        reference = Reference.query.filter(Reference.name == reference_name,
                                           Reference.type == 'other',
                                           Reference.workspace_id == obj.workspace_id).first()
        if not reference:
            try:
                reference = Reference(name=reference_name, type='other', workspace_id=obj.workspace_id)
                db.session.add(reference)
                db.session.commit()
            except IntegrityError as ex:
                if not is_unique_constraint_violation(ex):
                    logger.error("Could not create reference %s", reference_name)
                    logger.exception(ex)
                    continue
                logger.debug("Reference violated unique constraint. Rollback in progress")
                db.session.rollback()
                reference = Reference.query.filter(Reference.name == reference_name,
                                                   Reference.type == 'other',
                                                   Reference.workspace_id == obj.workspace_id).first()
                if not reference:
                    logger.error("Could not get reference")
                    continue
                logger.debug(f"Reference {reference.name} object finally obtained")
        obj.reference_instances.add(reference)


def add_policy_violations(obj, policy_violations):
    for policy_violation_name in policy_violations:
        policy_violation = PolicyViolation.query.filter(PolicyViolation.name == policy_violation_name,
                                                        PolicyViolation.workspace_id == obj.workspace_id).first()
        if not policy_violation:
            try:
                policy_violation = PolicyViolation(name=policy_violation_name, workspace_id=obj.workspace_id)
                db.session.add(policy_violation)
                db.session.commit()
            except IntegrityError as ex:
                if not is_unique_constraint_violation(ex):
                    logger.error("Could not create policy_violation %s", policy_violation_name)
                    logger.exception(ex)
                    continue
                logger.debug("PolicyViolation violated unique constraint. Rollback in progress")
                db.session.rollback()
                policy_violation = PolicyViolation.query.filter_by(name=policy_violation_name,
                                                                   workspace_id=obj.workspace_id).first()
                if not policy_violation:
                    logger.error("Could not get policy_violation")
                    continue
                logger.debug("PolicyViolation object finally obtained")
        obj.policy_violation_instances.add(policy_violation)


def create_policy_violation_obj(policy_violation_name, ws_id):
    policy_violation = PolicyViolation.query.filter(PolicyViolation.name == policy_violation_name,
                                                    PolicyViolation.workspace_id == ws_id).first()
    if not policy_violation:
        try:
            # nested = db.session.begin_nested()
            policy_violation = PolicyViolation(name=policy_violation_name,
                                               workspace_id=ws_id)
            db.session.add(policy_violation)
            db.session.commit()
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                logger.error("Could not create policy_violation %s", policy_violation_name)
                logger.exception(ex)
                return None
            logger.debug("PolicyViolation violated unique constraint. Rollback in progress")
            db.session.rollback()
            # nested.rollback()
            policy_violation = PolicyViolation.query.filter_by(name=policy_violation_name,
                                                               workspace_id=ws_id).first()
            if not policy_violation:
                logger.error("Could not get policy_violation")
                return None
            logger.debug("PolicyViolation object finally obtained")
    return policy_violation


def update_one_host_severity_stat(vulnerability):
    if not vulnerability:
        return None
    state = inspect(vulnerability)
    hosts = []
    services = []
    if state.attrs.host_id.history.added or state.attrs.service_id.history.added:
        if state.attrs.host_id.history.added:
            if state.attrs.host_id.history.added[0] is not None:
                hosts.append(state.attrs.host_id.history.added[0])
            if state.attrs.host_id.history.deleted[0] is not None:
                hosts.append(state.attrs.host_id.history.deleted[0])
        if state.attrs.service_id.history.added:
            if state.attrs.service_id.history.added[0] is not None:
                services.append(state.attrs.service_id.history.added[0])
            if state.attrs.service_id.history.deleted[0] is not None:
                services.append(state.attrs.service_id.history.deleted[0])
    elif state.attrs.severity.history.added:
        if vulnerability.host_id:
            hosts.append(vulnerability.host_id)
        elif vulnerability.service_id:
            hosts.append(vulnerability.service.host_id)
        else:
            logger.warning("Nor service nor host found in vulnerability ", vulnerability)
    return hosts, services


def bulk_update_custom_attributes(vuln_ids: list, data: dict):
    """
    Updates or adds specified custom attribute for a list of vulnerabilities without
    overwriting existing custom attributes.

    :param vuln_ids: List of vulnerability IDs to update.
    :param data: Dictionary of custom field to update/add.
    :return: Flask Response object
    """

    try:
        for key, value in data["custom_fields"].items():
            # Prepare the path and value for jsonb_set
            key_path = f'{{{key}}}'  # e.g., '{string}'
            value_json = json.dumps(value)
            # Perform the bulk update
            stmt = (
                update(VulnerabilityGeneric)
                .where(VulnerabilityGeneric.id.in_(vuln_ids))
                .values(
                    custom_fields=func.jsonb_set(
                        func.coalesce(VulnerabilityGeneric.custom_fields, '{}'),  # Handle NULLs
                        key_path,
                        value_json,
                        True  # Create missing
                    )
                )
            )
            db.session.execute(stmt)
        db.session.commit()
        return jsonify({"updated": len(vuln_ids)})

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)})
