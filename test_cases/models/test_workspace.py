from server.models import db, Workspace
from test_cases.factories import (
    HostFactory,
    ServiceFactory,
    SourceCodeFactory,
    VulnerabilityFactory,
    VulnerabilityCodeFactory,
    VulnerabilityWebFactory,
)

C_SOURCE_CODE_VULN_COUNT = 3
C_STANDARD_VULN_COUNT = [6, 2]  # With host parent and with service parent
C_WEB_VULN_COUNT = 5

NC_SOURCE_CODE_VULN_COUNT = 1
NC_STANDARD_VULN_COUNT = [1, 2]  # With host parent and with service parent
NC_WEB_VULN_COUNT = 2

SOURCE_CODE_VULN_COUNT = C_SOURCE_CODE_VULN_COUNT + NC_SOURCE_CODE_VULN_COUNT
STANDARD_VULN_COUNT = C_STANDARD_VULN_COUNT + NC_STANDARD_VULN_COUNT
WEB_VULN_COUNT = C_WEB_VULN_COUNT + NC_WEB_VULN_COUNT


def populate_workspace(workspace):
    host = HostFactory.create(workspace=workspace)
    service = ServiceFactory.create(workspace=workspace, host=host)
    code = SourceCodeFactory.create(workspace=workspace)

    # Create non confirmed vulnerabilities

    # Create standard vulns
    VulnerabilityFactory.create_batch(
        NC_STANDARD_VULN_COUNT[0], workspace=workspace, host=host,
        service=None, confirmed=False)
    VulnerabilityFactory.create_batch(
        NC_STANDARD_VULN_COUNT[1], workspace=workspace, service=service,
        host=None, confirmed=False)

    # Create web vulns
    VulnerabilityWebFactory.create_batch(
        NC_WEB_VULN_COUNT, workspace=workspace, service=service,
        confirmed=False)

    # Create source code vulns
    VulnerabilityCodeFactory.create_batch(
        NC_SOURCE_CODE_VULN_COUNT, workspace=workspace, source_code=code,
        confirmed=False)

    # Create confirmed vulnerabilities

    # Create standard vulns
    VulnerabilityFactory.create_batch(
        C_STANDARD_VULN_COUNT[0], workspace=workspace, host=host, service=None,
        confirmed=True)
    VulnerabilityFactory.create_batch(
        C_STANDARD_VULN_COUNT[1], workspace=workspace, service=service,
        host=None, confirmed=True)

    # Create web vulns
    VulnerabilityWebFactory.create_batch(
        C_WEB_VULN_COUNT, workspace=workspace, service=service, confirmed=True)

    # Create source code vulns
    VulnerabilityCodeFactory.create_batch(
        C_SOURCE_CODE_VULN_COUNT, workspace=workspace, source_code=code,
        confirmed=True)

    db.session.commit()


def test_vuln_count(workspace, second_workspace):
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query_with_count(False).filter(
        Workspace.id == workspace.id).first()
    assert workspace.vulnerability_web_count == WEB_VULN_COUNT
    assert workspace.vulnerability_code_count == SOURCE_CODE_VULN_COUNT
    assert workspace.vulnerability_standard_count == sum(
        STANDARD_VULN_COUNT)
    assert workspace.vulnerability_total_count == (
        sum(STANDARD_VULN_COUNT) + WEB_VULN_COUNT +
        SOURCE_CODE_VULN_COUNT
    )


def test_vuln_count_confirmed(workspace, second_workspace):
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query_with_count(True).filter(
        Workspace.id == workspace.id).first()
    assert workspace.vulnerability_web_count == C_WEB_VULN_COUNT
    assert workspace.vulnerability_code_count == C_SOURCE_CODE_VULN_COUNT
    assert workspace.vulnerability_standard_count == sum(
        C_STANDARD_VULN_COUNT)
    assert workspace.vulnerability_total_count == (
        sum(C_STANDARD_VULN_COUNT) + C_WEB_VULN_COUNT +
        C_SOURCE_CODE_VULN_COUNT
    )


def test_vuln_no_count(workspace, second_workspace):
    populate_workspace(workspace)
    populate_workspace(second_workspace)
    workspace = Workspace.query.get(workspace.id)
    assert workspace.vulnerability_web_count is None
    assert workspace.vulnerability_code_count is None
    assert workspace.vulnerability_standard_count is None
    assert workspace.vulnerability_total_count is None
