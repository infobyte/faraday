'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest

from faraday.server.models import Role
from tests.conftest import login_as


@pytest.mark.usefixtures('logged_user')
class TestSessionLogged:
    def test_session_when_user_is_logged(self, test_client):
        res = test_client.get('/session')
        assert res.status_code == 200

    @pytest.mark.parametrize('role', ['admin', 'pentester', 'client', 'asset_owner'])
    def test_session_when_user_is_logged_with_different_roles(self, test_client, session, user, role):
        user.roles = [Role.query.filter(Role.name == role).one()]
        session.commit()
        login_as(test_client, user)
        res = test_client.get('/session')
        assert role in res.json['roles']


class TestSessionNotLogged:
    def test_session_when_user_is_not_logged(self, test_client):
        res = test_client.get('/session')
        assert res.status_code == 401
