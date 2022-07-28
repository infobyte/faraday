import logging

from cvss import CVSS3

logger = logging.getLogger(__name__)


def get_score(cvss_instance, score: str) -> [None, float]:
    valid_scores = ['B', 'T', 'E']
    if score not in valid_scores:
        raise ValueError('Score must be one of %s', ', '.join(valid_scores))
    index = valid_scores.index(score)
    return cvss_instance.scores()[index]


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
