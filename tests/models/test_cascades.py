'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import pytest
from contextlib import contextmanager
from faraday.server.models import (
    CommandObject,
    Comment,
    File,
    Methodology,
    MethodologyTemplate,
    Task,
    TaskAssignedTo,
    TaskTemplate,
    WorkspacePermission,
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
        self.permission = WorkspacePermission(user=user, workspace=workspace)
        session.add(self.permission)
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
            content=b'test',
            object_type='vulnerability',
            object_id=self.service_vuln.id,
            creator=user,
        )
        self.session.add(self.attachment)

        self.host_attachment = File(
            name='test.png',
            filename='test.png',
            content=b'test',
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

        self.methodology_template = MethodologyTemplate(
            name="test",
        )
        session.add(self.methodology_template)

        self.methodology_template_task = TaskTemplate(
            name="aaaa",
            template=self.methodology_template
        )
        session.add(self.methodology_template)

        self.methodology = Methodology(
            name="test",
            template=self.methodology_template,
            workspace=self.workspace)
        session.add(self.methodology)

        self.methodology_task = Task(
            name="aaaa",
            workspace=self.workspace,
            template=self.methodology_template_task,
            methodology=self.methodology
        )
        session.add(self.methodology_template_task)

        self.methodology_task_assigned = TaskAssignedTo(
            task=self.methodology_task,
            user=self.user,
        )
        session.add(self.methodology_task_assigned)

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

        with self.assert_deletes(self.permission):
            with self.assert_deletes(self.user, should_delete=False):
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
            with self.assert_deletes(self.permission):
                self.session.delete(self.user)
        for obj in objs:
            assert obj.creator is None

    def test_delete_service_keeps_parents(self):
        with self.assert_deletes(self.host, self.user, self.workspace,
                                 should_delete=False):
            self.session.delete(self.service)

    def test_delete_methodology_template_keeps_child(self):
        with self.assert_deletes(self.methodology, self.methodology_task,
                                 should_delete=False):
            self.session.delete(self.methodology_template)

    def test_delete_methodology_template_deletes_task(self):
        with self.assert_deletes(self.methodology_template_task):
            self.session.delete(self.methodology_template)

    def test_delete_task_deletes_assignations(self):
        with self.assert_deletes(self.methodology_task_assigned):
            self.session.delete(self.methodology_task)

    def test_delete_task_assignation_keeps_user(self):
        with self.assert_deletes(self.user, should_delete=False):
            self.session.delete(self.methodology_task_assigned)

    def test_delete_user_deletes_assignations(self):
        with self.assert_deletes(self.methodology_task_assigned):
            self.session.delete(self.user)
