import random
import pytest
from functools import partial


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
