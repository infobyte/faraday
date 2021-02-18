'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from faraday.server.api.modules.comments import CommentView, CommentV3View
from faraday.server.models import Comment
from tests.factories import ServiceFactory
from tests.test_api_workspaced_base import ReadWriteAPITests, V3TestMixin
from tests import factories
from tests.utils.url import v2_to_v3


class TestCommentAPIGeneric(ReadWriteAPITests):
    model = Comment
    factory = factories.CommentFactory
    view_class = CommentView
    api_endpoint = 'comment'
    update_fields = ['text']
    patchable_fields = ['text']

    def check_url(self, url):
        return url

    def _create_raw_comment(self, object_type, object_id):
        return {
            'object_id': object_id,
            'object_type': object_type,
            'description': '',
            'metadata': {
                'command_id': '',
                'create_time': 1513093980.157945,
                'creator': 'Nmap',
                'owner': '',
                'update_action': 0,
                'update_controller_action': 'No model controller call',
                'update_time': 1513093980.157948,
                'update_user': ''
            },
            'name': 'website',
            'owned': False,
            'owner': '',
            'text': '',
            'type': 'Note'
        }

    def test_create_comment_from_plugins(self, test_client, session):
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        initial_comment_count = len(session.query(Comment).all())
        raw_comment = self._create_raw_comment('service', service.id)
        res = test_client.post(self.url(workspace=self.workspace), data=raw_comment)
        assert res.status_code == 201
        assert len(session.query(Comment).all()) == initial_comment_count + 1

    def test_cannot_create_comment__with_invalid_object_type(self, test_client, session):
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        raw_comment = self._create_raw_comment('workspace', service.id)
        res = test_client.post(self.url(), data=raw_comment)
        assert res.status_code == 400
        assert 'Must be one of' in res.json['messages']['json']['object_type'][0]

    def test_cannot_create_comment_of_another_workspace_object(self, test_client, session, second_workspace):
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        raw_comment = self._create_raw_comment('service', service.id)
        res = test_client.post(self.url(workspace=second_workspace), data=raw_comment)
        assert res.status_code == 400
        assert res.json == {u'message': u"Can't comment object of another workspace"}

    def test_cannot_create_comment_of_inexistent_object(self, test_client, session):
        raw_comment = self._create_raw_comment('service', 456464556)
        res = test_client.post(self.url(workspace=self.workspace), data=raw_comment)
        assert res.status_code == 400
        assert res.json == {u'message': u"Can't comment inexistent object"}


    def test_create_unique_comment_for_plugins(self, session, test_client):
        """


        """
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        initial_comment_count = len(session.query(Comment).all())
        raw_comment = self._create_raw_comment('service', service.id)
        res = test_client.post(self.url(workspace=self.workspace),
                               data=raw_comment)
        assert res.status_code == 201
        assert len(session.query(Comment).all()) == initial_comment_count + 1

        url = self.check_url(self.url(workspace=self.workspace).strip('/') + '_unique/')
        res = test_client.post(url, data=raw_comment)
        assert res.status_code == 409
        assert 'object' in res.json
        assert type(res.json) == dict

    def test_create_unique_comment_for_plugins_after_and_before(self, session, test_client):
        """


        """
        service = ServiceFactory.create(workspace=self.workspace)
        session.commit()
        initial_comment_count = len(session.query(Comment).all())
        raw_comment = self._create_raw_comment('service', service.id)
        url = self.check_url(self.url(workspace=self.workspace).strip('/') + '_unique/')
        res = test_client.post(url,
                               data=raw_comment)
        assert res.status_code == 201
        assert len(session.query(Comment).all()) == initial_comment_count + 1

        res = test_client.post(url, data=raw_comment)
        assert res.status_code == 409
        assert 'object' in res.json
        assert type(res.json) == dict

    def test_default_order_field(self, session, test_client):
        workspace = factories.WorkspaceFactory.create()
        factories.CommentFactory.create(workspace=workspace, text='first')
        factories.CommentFactory.create(workspace=workspace, text='second')
        factories.CommentFactory.create(workspace=workspace, text='third')
        factories.CommentFactory.create(workspace=workspace, text='fourth')
        get_comments = test_client.get(self.url(workspace=workspace))
        expected = ['first', 'second', 'third','fourth']
        assert expected == [comment['text'] for comment in get_comments.json]


class TestCommentAPIGenericV3(TestCommentAPIGeneric, V3TestMixin):
    view_class = CommentV3View

    def url(self, obj=None, workspace=None):
        return v2_to_v3(super(TestCommentAPIGenericV3, self).url(obj, workspace))

    def check_url(self, url):
        return v2_to_v3(url)
