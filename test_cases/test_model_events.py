import pytest
from test_cases.factories import HostFactory, ServiceFactory


def test_child_parent_verification_event_fails(session, workspace,
                                               second_workspace):
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=second_workspace)
    with pytest.raises(AssertionError):
        session.commit()


def test_child_parent_verification_event_succeeds(session, workspace):
    """
        Asserts that no exception will be raised when workspace are the same.
    """
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=workspace)
    session.commit()
