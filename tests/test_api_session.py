'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import pytest

@pytest.mark.usefixtures('logged_user')
class TestSessionLogged():
    def test_session_when_user_is_logged(self, test_client):
        res = test_client.get('/session')
        assert res.status_code == 200

class TestSessionNotLogged():
    def test_session_when_user_is_not_logged(self, test_client):
        res = test_client.get('/session')
        assert res.status_code == 401


# I'm Py3
