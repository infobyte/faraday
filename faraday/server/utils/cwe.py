import re
import logging

from faraday.server.models import db, CWE
from faraday.server.utils.database import get_or_create

CWE_FORMAT = r'^CWE-\d{1,}$'

logger = logging.getLogger(__name__)


def create_cwe(cwe_list: list = []) -> list:
    cwe_obj_set = set()
    for cwe in cwe_list:
        if re.findall(CWE_FORMAT, cwe['name'], re.IGNORECASE):
            cwe_obj, _ = get_or_create(db.session, CWE, name=cwe['name'].upper())
            cwe_obj_set.add(cwe_obj)
        else:
            logger.warning("CWE (%s) did not match format", cwe)
    return list(cwe_obj_set)
