import random
import pytest
from functools import partial
from server.models import Hostname


@pytest.mark.parametrize(
    "with_host_vulns,with_service_vulns", [[True, False],
                                           [False, True],
                                           [True, True]],
    ids=["with host vulnerabilities",
         "with service vulnerabilities",
         "with host and service vulnerabilities"]
)
def test_vulnerability_count(with_host_vulns, with_service_vulns, host,
                             session, service_factory,
                             vulnerability_factory, vulnerability_web_factory):
    expected_count = 0

    if with_host_vulns:
        vulnerability_factory.create_batch(8, host=host, service=None,
                                           workspace=host.workspace)
        expected_count += 8

    if with_service_vulns:
        services = service_factory.create_batch(10, workspace=host.workspace,
                                                host=host)
        for service in services:
            for _ in range(5):
                # Randomly pick between a standard or a web vuln
                create = random.choice([
                    vulnerability_web_factory.create,
                    partial(vulnerability_factory.create, host=None)
                ])
                create(
                    service=service,
                    workspace=host.workspace
                )
                expected_count += 1

    session.commit()
    assert host.vulnerability_count == expected_count


class TestUpdateHostnames:
    """This class tests the generic set_children_objects function and
    not only the Host model logic. Think twice if you are going to
    remove this"""
    # set_children = partial(set_children_objects, attr='hostnames', key='name')

    def test_set_from_empty_host(self, host, session):
        session.commit()
        assert len(host.hostnames) == 0
        host.set_hostnames(['test.com', 'other.com'])
        assert len(session.new) == 2
        session.commit()
        assert len(host.hostnames) == 2
        assert {hn.name for hn in host.hostnames} == {'test.com', 'other.com'}

    def test_set_to_empty_host(self, host_with_hostnames, session):
        session.commit()
        n_hostnames = len(host_with_hostnames.hostnames)
        host_with_hostnames.set_hostnames([])
        assert len(session.deleted) == n_hostnames
        session.commit()
        assert host_with_hostnames.hostnames == []

    def test_stays_equal(self, host_with_hostnames, session):
        new_value = [hn.name for hn in host_with_hostnames.hostnames]
        random.shuffle(new_value)
        host_with_hostnames.set_hostnames(new_value)
        session.commit()
        assert len(session.new) == len(session.deleted) == len(
            session.dirty) == 0
        assert set(new_value) == set(hn.name for hn in
                                     host_with_hostnames.hostnames)

    def test_all(self, host, session):
        a = Hostname(workspace=host.workspace, host=host, name='a')
        b = Hostname(workspace=host.workspace, host=host, name='b')
        session.add(a)
        session.add(b)
        session.commit()

        host.set_hostnames(['b', 'c'])

        # a should be deleted
        assert len(session.deleted) == 1
        assert session.deleted.pop() is a

        # c should be created
        assert len(session.new) == 1
        c = session.new.pop()
        assert c.name == 'c'

        session.commit()
        assert set(hn.name for hn in host.hostnames) == {'b', 'c'}
