import logging
from decimal import Decimal as D

from cvss import CVSS3
from cvss.cvss2 import round_to_1_decimal
from cvss.cvss3 import round_up

logger = logging.getLogger(__name__)


def get_special_score(cvss_instance, index: int) -> [None, float]:
    cvss2_functions = [lambda cvss2: round_to_1_decimal(cvss2.impact_equation()),
                       lambda cvss2: round_to_1_decimal(D('20') * cvss2.get_value('AV') * cvss2.get_value('AC') * cvss2.get_value('Au'))]
    cvss3_functions = [lambda cvss3: round_up(cvss3.isc), lambda cvss3: round_up(cvss3.esc)]

    if isinstance(cvss_instance, CVSS3):
        return cvss3_functions[index](cvss_instance)
    return cvss2_functions[index](cvss_instance)


def get_score(cvss_instance, score: str) -> [None, float]:
    valid_scores = ['B', 'T', 'E']
    special_scores = ['Im', 'Ex']

    if score in special_scores:
        return get_special_score(cvss_instance, special_scores.index(score))

    if score not in valid_scores:
        raise ValueError('Score must be one of %s', ', '.join(valid_scores + special_scores))

    index = valid_scores.index(score)
    return cvss_instance.scores()[index]


def get_base_score(cvss_instance) -> [None, float]:
    return get_score(cvss_instance, 'B')


def get_temporal_score(cvss_instance) -> [None, float]:
    return get_score(cvss_instance, 'T')


def get_environmental_score(cvss_instance) -> [None, float]:
    return get_score(cvss_instance, 'E')


def get_impact_score(cvss_instance) -> [None, float]:
    return get_score(cvss_instance, 'Im')


def get_exploitability_score(cvss_instance) -> [None, float]:
    return get_score(cvss_instance, 'Ex')


def get_severity(cvss_instance, severity: str) -> [None, str]:
    valid_severities = ['B', 'T', 'E']
    if severity not in valid_severities:
        raise ValueError('Severity must be one of %s', ', '.join(valid_severities))
    index = valid_severities.index(severity)
    return cvss_instance.severities()[index].lower() if cvss_instance.severities()[index] != 'None' else None


def get_propper_value(cvss_instance, attr: str) -> [None, str]:
    if cvss_instance.get_value_description(attr) == 'Not Defined':
        return None
    if isinstance(cvss_instance, CVSS3) and not attr_exists_in_vector(cvss_instance, attr):
        return None
    return cvss_instance.get_value_description(attr).lower()


def attr_exists_in_vector(cvss_instance, attr):
    if attr in cvss_instance.original_metrics:
        return True
    return False
