from faraday.server.models import db, CWE
from faraday.server.utils.database import get_or_create


def create_cwe(cwe_list: list = []) -> list:
    cwe_obj_set = set()
    for cwe in cwe_list:
        cwe_obj, _ = get_or_create(db.session, CWE, name=cwe['name'].upper())
        cwe_obj_set.add(cwe_obj)
    return list(cwe_obj_set)
