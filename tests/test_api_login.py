from tests import factories

class TestLogin():
    def test_case_bug_with_username(self, test_client, session):
        """
            When the user case does not match the one in database,
            the form is valid but no record was found in the database.
        """

        susan = factories.UserFactory.create(
                active=True,
                username='Susan',
                password='pepito',
                role='pentester')
        session.add(susan)
        session.commit()
        # we use lower case username, but in db is Capitalized
        login_payload = {
            'email': 'susan',
            'password': 'pepito',
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']

    def test_case_ws_with_valid_authentication_token(self, test_client, session):
        """
            Use of a valid auth token
        """

        alice = factories.UserFactory.create(
                active=True,
                username='alice',
                password='passguord',
                role='pentester')
        session.add(alice)
        session.commit()

        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()

        login_payload = {
            'email': 'alice',
            'password': 'passguord',
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']
        
        headers = {'Authentication-Token': res.json['response']['user']['authentication_token']}

        ws = test_client.get('/v2/ws/wonderland/', headers=headers)
        assert ws.status_code == 200

    def test_case_ws_with_invalid_authentication_token(self, test_client, session):
        """
            Use of an invalid auth token
        """

        alice = factories.UserFactory.create(
                active=True,
                username='alice',
                password='passguord',
                role='pentester')
        session.add(alice)
        session.commit()

        ws = factories.WorkspaceFactory.create(name='wonderland')
        session.add(ws)
        session.commit()

        login_payload = {
            'email': 'alice',
            'password': 'passguord',
        }
        res = test_client.post('/login', data=login_payload)
        assert res.status_code == 200
        assert 'authentication_token' in res.json['response']['user']
        
        headers = {'Authentication-Token': 'hajimemashite'}

        ws = test_client.get('/v2/ws/wonderland/', headers=headers)
        assert ws.status_code == 401
