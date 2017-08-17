import os
import sys
sys.path.append(os.path.abspath(os.getcwd()))
import string
import random
import unittest

from server.dao.credential import CredentialDAO
from test_cases.factories import WorkspaceFactory, CredentialFactory


def test_list_with_multiple_workspace(app, session):
    with app.app_context():
        workspace = WorkspaceFactory.build()

        credentials_dao = CredentialDAO(workspace)
        expected = {'rows': []}

        res = credentials_dao.list()
        assert expected == res

        credential = CredentialFactory.build(workspace=workspace)
        session.add(credential)
        session.commit()
        expected = {}
        res = credentials_dao.list()
        expected = {'rows': [{'value': {'username': credential.username, 'password': credential.password, 'description': None, 'couchid': None, 'owner': None, '_id': None, 'metadata': {'update_time': None, 'create_time': None, 'update_user': None, 'update_action': None, 'creator': None, 'owner': None, 'update_controller_action': None, 'command_id': None}, 'owned': None, 'name': None}, 'id': None, 'key': None}]}

        assert expected == res

        another_workspace = WorkspaceFactory.build()

        another_credential = CredentialFactory.build(workspace=another_workspace)
        session.add(another_credential)
        session.commit()

        res = credentials_dao.list()
        assert expected == res
