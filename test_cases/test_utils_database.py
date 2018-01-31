import pytest

from server.utils.database import get_unique_fields
from server.models import (
    License,
    Service,
    Host,
    Vulnerability,
    Workspace,
)

UNIQUE_FIELDS = {
    License: [u'product', u'start_date', u'end_date'],
    Service: [u'port', u'protocol', u'host_id', u'workspace_id'],
    Host: [u'ip', u'workspace_id'],
    Vulnerability: [
        'name',
        'description',
        'host_id',
        'service_id',
        'method',
        'parameter_name',
        'path',
        'website',
        'workspace_id',
    ],
    Workspace: ['name']
}


@pytest.mark.parametrize("obj_class, expected_unique_fields", UNIQUE_FIELDS.items())
def test_unique_fields_workspace(obj_class, expected_unique_fields, session):
    workspace = obj_class()
    unique_constraints = get_unique_fields(session, workspace)
    for unique_constraint in unique_constraints:
        assert unique_constraint == expected_unique_fields