from server import events
from test_cases.factories import HostFactory, ServiceFactory


def test_child_parent_verification_event(session, workspace, second_workspace):
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=second_workspace)
    try:
        session.commit()
    except AssertionError:
        return True
    return False

def test_child_parent_verification_event(session, workspace):
    host = HostFactory.build(workspace=workspace)
    ServiceFactory.build(host=host, workspace=workspace)
    session.commit()
    return True