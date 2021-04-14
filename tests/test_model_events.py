'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest
from tests.factories import HostFactory, ServiceFactory
from faraday.server.models import Host, Workspace


def test_child_parent_verification_event_fails(session, workspace,
                                               second_workspace):
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=second_workspace)
    with pytest.raises(AssertionError):
        session.commit()

    session.rollback()

    assert session.query(Host).filter(
            Workspace.id == workspace.id
        ).first() is None


def test_child_parent_verification_event_succeeds(session, workspace):
    """
        Asserts that no exception will be raised when workspace are the same.
    """
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=workspace)
    session.commit()


def test_child_parent_verification_event_fails_update(session, workspace,
                                                      second_workspace):
    host = HostFactory.build(workspace=workspace)
    service = ServiceFactory.build(host=host, workspace=workspace)
    session.commit()
    service.workspace = second_workspace
    session.add(service)
    with pytest.raises(AssertionError):
        session.commit()


def test_child_parent_verification_event_succeds_update(session, workspace):
    host = HostFactory.build(workspace=workspace)
    service = ServiceFactory.build(host=host, workspace=workspace)
    session.commit()
    service.workspace = workspace
    session.add(service)
    session.commit()


def test_child_parent_verification_event_changing_id_fails(session, workspace,
                                                           second_workspace):

    session.add(workspace)
    session.add(second_workspace)
    session.commit()
    host = HostFactory.build(workspace=workspace)
    session.add(host)
    session.commit()
    service = ServiceFactory.build(host=host, workspace_id=second_workspace.id)

    session.add(service)

    with pytest.raises(AssertionError):
        session.commit()


# I'm Py3
