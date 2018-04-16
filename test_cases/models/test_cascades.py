import pytest
from contextlib import contextmanager
from server.models import CommandObject, File

def test_delete_user(workspace, session):
    assert workspace.creator
    session.commit()
    user = workspace.creator
    session.delete(user)
    session.commit()
    assert workspace.creator is None


class TestCascadeDelete:
    @pytest.fixture(autouse=True)
    def populate(self, workspace, service, session,
                 vulnerability_factory, credential_factory,
                 empty_command_factory):
        session.commit()
        self.session = session
        assert service.workspace_id == workspace.id

        workspace.set_scope(['*.infobytesec.com', '192.168.1.0/24'])
        self.workspace = workspace
        self.host = service.host
        self.host.set_hostnames(['a.com', 'b.com'])
        self.service = service

        self.host_cred = credential_factory.create(
            host=self.host,
            service=None,
            workspace=workspace
        )

        self.service_cred = credential_factory.create(
            host=None,
            service=service,
            workspace=workspace
        )

        self.host_vuln = vulnerability_factory.create(
            host=self.host,
            service=None,
            workspace=workspace,
        )

        self.service_vuln = vulnerability_factory.create(
            host=None,
            service=service,
            workspace=workspace,
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
        )
        self.session.add(self.attachment)

        self.host_attachment = File(
            name='test.png',
            filename='test.png',
            content='test',
            object_type='host',
            object_id=self.host.id,
        )
        self.session.add(self.host_attachment)

        self.command = empty_command_factory.create(workspace=workspace)
        CommandObject.create(self.host_vuln, self.command)
        CommandObject.create(self.service_vuln, self.command)

        session.commit()

    @contextmanager
    def assert_deletes(self, *objs):
        assert all(obj.id is not None for obj in objs)
        ids = [(obj.__table__, obj.id) for obj in objs]
        yield
        self.session.commit()
        for (table, id_) in ids:
            assert self.session.query(table).filter(
                table.columns['id'] == id_).count() == 0

    def test_delete_host_cascade(self):
        with self.assert_deletes(self.host, self.service,
                                 self.host_vuln, self.service_vuln,
                                 self.host_cred, self.service_cred):
            self.session.delete(self.host)

    def test_delete_workspace(self):
        self.session.delete(self.workspace)
        self.session.commit()

    def test_delete_vuln_attachments(self):
        with self.assert_deletes(self.attachment):
            self.session.delete(self.service_vuln)

    def test_delete_host_attachments(self):
        with self.assert_deletes(self.host_attachment):
            self.session.delete(self.host)
