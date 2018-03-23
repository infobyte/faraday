
def test_delete_user(workspace, session):
    assert workspace.creator
    session.commit()
    user = workspace.creator
    session.delete(user)
    session.commit()
    assert workspace.creator is None
