import pytest
from server.models import db
from test_cases.factories import (
    HostFactory,
    ServiceFactory,
    SourceCodeFactory,
    VulnerabilityFactory,
    VulnerabilityCodeFactory,
    VulnerabilityWebFactory,
)

SOURCE_CODE_VULN_COUNT = 3
STANDARD_VULN_COUNT = [6, 2]  # With host parent and with service parent
WEB_VULN_COUNT = 5


def populate_workspace(workspace):
    host = HostFactory.create(workspace=workspace)
    service = ServiceFactory.create(workspace=workspace, host=host)
    code = SourceCodeFactory.create(workspace=workspace)

    # Create standard vulns
    host_vulns = VulnerabilityFactory.create_batch(
        STANDARD_VULN_COUNT[0], workspace=workspace, host=host)
    service_vulns = VulnerabilityFactory.create_batch(
        STANDARD_VULN_COUNT[1], workspace=workspace, service=service)

    # Create web vulns
    web_vulns = VulnerabilityWebFactory.create_batch(
        WEB_VULN_COUNT, workspace=workspace, service=service)

    # Create source code vulns
    code_vulns = VulnerabilityCodeFactory.create_batch(
        SOURCE_CODE_VULN_COUNT, workspace=workspace, source_code=code)

    db.session.commit()


def test_vuln_count(workspace, second_workspace):
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    assert workspace.vulnerability_web_count == WEB_VULN_COUNT
    assert workspace.vulnerability_code_count == SOURCE_CODE_VULN_COUNT
    assert workspace.vulnerability_standard_count == sum(STANDARD_VULN_COUNT)
    assert workspace.vulnerability_total_count == (
        sum(STANDARD_VULN_COUNT) + WEB_VULN_COUNT + SOURCE_CODE_VULN_COUNT
    )
