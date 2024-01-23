import re
import logging

from sqlalchemy.exc import IntegrityError

from faraday.server.models import db, CWE
from faraday.server.utils.database import is_unique_constraint_violation

CWE_FORMAT = r'^CWE-\d{1,}$'

logger = logging.getLogger(__name__)


# TODO: Generalize get_or_create with exception handling.
def get_or_create_cwe(cwe_name: str) -> [None, CWE]:
    # We expect that cwe_name is not empty
    # Just in case.
    if not cwe_name:
        return None
    cwe = CWE.query.filter(CWE.name == cwe_name).first()
    if not cwe:
        try:
            cwe = CWE(name=cwe_name)
            db.session.add(cwe)
            db.session.commit()
        except IntegrityError as ex:
            if not is_unique_constraint_violation(ex):
                logger.error("Could not create cwe %s", cwe_name)
                return None
            logger.debug("CWE violated unique constraint. Rollback in progress")
            db.session.rollback()
            cwe = CWE.query.filter(CWE.name == cwe_name).first()
            if not cwe:
                logger.error("Could not get cwe")
                return None
            logger.debug("CWE object finally obtained")
    return cwe


def create_cwe(cwe_list: list = []) -> list:
    cwe_obj_set = set()
    for cwe in cwe_list:
        if re.findall(CWE_FORMAT, cwe['name'], re.IGNORECASE):
            cwe_obj = get_or_create_cwe(cwe_name=cwe['name'].upper())
            if not cwe_obj:
                logger.error("Could not create cwe")
                continue
            cwe_obj_set.add(cwe_obj)
        else:
            logger.warning("CWE (%s) did not match format", cwe)
    return list(cwe_obj_set)
