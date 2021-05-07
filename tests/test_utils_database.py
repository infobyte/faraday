'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest

from faraday.server.utils.database import get_unique_fields
from faraday.server.models import (
    License,
    Service,
    Host,
    Vulnerability,
    Workspace,
    vulnerability_uniqueness
)

UNIQUE_FIELDS = {
    License: [u'product', u'start_date', u'end_date'],
    Service: [u'port', u'protocol', u'host_id', u'workspace_id'],
    Host: [u'ip', u'workspace_id'],
    Vulnerability: [
        'name',
        'description',
        'type',
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


def test_vulnerability_ddl_invariant(session):
    """
        This test is to make sure that get_unique_fields for Vulnerability is
        returning the same columns as in the DDL
    :return:
    """
    statement = vulnerability_uniqueness.statement
    column_part = statement.split('%(fullname)s')[1]
    statements_clean = column_part.strip().strip(')').strip('(').split(',')
    statements_clean = [column.replace('COALESCE(', '').replace('md5(', '').strip('(') for column in statements_clean]
    statements_clean = \
        list(
            filter(len,
                   map(lambda column: column.strip("'')").strip('-1').strip('-1));').strip(), statements_clean)
                   )
        )
    statements_clean.remove('source_code_id')  # we don't support source_code yet
    unique_constraints = get_unique_fields(session, Vulnerability())
    for unique_constraint in unique_constraints:
        assert len(statements_clean) == len(unique_constraint)
        for statement_clean in statements_clean:
            statement_clean = statement_clean
            if statement_clean not in unique_constraint:
                raise Exception('Please check server.utils.database.get_unique_fields. Vulnerability DDL changed?')


@pytest.mark.parametrize("obj_class, expected_unique_fields", list(UNIQUE_FIELDS.items()))
def test_unique_fields_workspace(obj_class, expected_unique_fields, session):
    object_ = obj_class()
    unique_constraints = get_unique_fields(session, object_)
    for unique_constraint in unique_constraints:
        assert unique_constraint == expected_unique_fields

# I'm Py3
