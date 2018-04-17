import pytest
from contextlib import contextmanager
from server.models import (
    CommandObject,
    Comment,
    File,
    Methodology,
    Task
)

def test_delete_user(workspace, session):
    assert workspace.creator
    session.commit()
    user = workspace.creator
    session.delete(user)
    session.commit()
    assert workspace.creator is None


class TestCascadeDelete:
    @pytest.fixture(autouse=True)
    def populate(self, workspace, service, session, user,
                 vulnerability_factory, credential_factory,
                 empty_command_factory):
        session.commit()
        self.session = session
        assert service.workspace_id == workspace.id

        workspace.set_scope(['*.infobytesec.com', '192.168.1.0/24'])
        self.user = user
        self.workspace = workspace
        self.host = service.host
        self.host.set_hostnames(['a.com', 'b.com'])
        self.service = service

        self.host_cred = credential_factory.create(
            host=self.host,
            service=None,
            workspace=workspace,
            creator=user,
        )

        self.service_cred = credential_factory.create(
            host=None,
            service=service,
            workspace=workspace,
            creator=user,
        )

        self.host_vuln = vulnerability_factory.create(
            host=self.host,
            service=None,
            workspace=workspace,
            creator=user,
        )

        self.service_vuln = vulnerability_factory.create(
            host=None,
            service=service,
            workspace=workspace,
            creator=user,
        )

        session.flush()
        for vuln in [self.host_vuln, self.service_vuln]:
            vuln.references = ['CVE-1234', 'CVE-4331']
            vuln.policy_violations = ["PCI-DSS"]

        self.attachment = File(
            name='test.png',
            filename='test.png',
            content='test',
            object_type='vulnerability',
            object_id=self.service_vuln.id,
            creator=user,
        )
        self.session.add(self.attachment)

        self.host_attachment = File(
            name='test.png',
            filename='test.png',
            content='test',
            object_type='host',
            object_id=self.host.id,
            creator=user,
        )
        self.session.add(self.host_attachment)

        self.comment = Comment(
            text="test",
            object_type='host',
            object_id=self.host.id,
            workspace=self.workspace,
            creator=user,
        )
        self.session.add(self.comment)

        self.reply_comment = Comment(
            text="ok",
            object_type='host',
            object_id=self.host.id,
            workspace=self.workspace,
            reply_to=self.comment,
            creator=user,
        )

        self.command = empty_command_factory.create(
            workspace=workspace,
            creator=user)
        CommandObject.create(self.host_vuln, self.command)
        CommandObject.create(self.service_vuln, self.command)

        session.commit()

    @contextmanager
    # def assert_deletes(self, *objs, should_delete=True):
    def assert_deletes(self, *objs, **kwargs):
        # this could be better with python3 (like in the comment before the function
        # definition)
        should_delete = kwargs.get('should_delete', True)
        assert all(obj.id is not None for obj in objs)
        ids = [(obj.__table__, obj.id) for obj in objs]
        yield
        self.session.commit()
        for (table, id_) in ids:
            if should_delete:
                expected_count = 0
            else:
                expected_count = 1
            assert self.session.query(table).filter(
                table.columns['id'] == id_).count() == expected_count

    def test_delete_host_cascade(self):
        with self.assert_deletes(self.host, self.service,
                                 self.host_vuln, self.service_vuln,
                                 self.host_cred, self.service_cred):
            self.session.delete(self.host)

    def test_delete_workspace(self, user):
        methodology = Methodology(name='test', workspace=self.workspace)
        task = Task(methodology=methodology, assigned_to=[user],
                    name="test",
                    workspace=self.workspace)
        self.session.add(task)
        self.session.commit()

        self.session.delete(self.workspace)
        self.session.commit()

    def test_delete_vuln_attachments(self):
        with self.assert_deletes(self.attachment):
            self.session.delete(self.service_vuln)

    def test_host_comments(self):
        with self.assert_deletes(self.comment, self.reply_comment):
            self.session.delete(self.host)

    def test_delete_host_attachments(self):
        with self.assert_deletes(self.host_attachment):
            self.session.delete(self.host)

    def test_delete_user_does_not_delete_childs(self):
        objs = [self.workspace, self.host, self.service,
                self.host_cred, self.service_cred,
                self.host_vuln, self.service_vuln,
                self.attachment, self.host_attachment,
                self.comment, self.reply_comment,
                self.command]
        for obj in objs:
            assert obj.creator is not None
        with self.assert_deletes(*objs, should_delete=False):
            self.session.delete(self.user)
        for obj in objs:
            assert obj.creator is None
