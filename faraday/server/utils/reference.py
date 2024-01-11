import logging

from faraday.server.models import db, VulnerabilityReference
from faraday.server.utils.database import get_or_create


logger = logging.getLogger(__name__)


def create_reference(reference_list: list = [], vulnerability_id=None) -> list:
    reference_obj_set = set()
    for reference in reference_list:
        reference_obj, _ = get_or_create(db.session, VulnerabilityReference, name=reference['name'],
                                         vulnerability_id=vulnerability_id,
                                         type=reference['type'])
        reference_obj_set.add(reference_obj)
    return list(reference_obj_set)
