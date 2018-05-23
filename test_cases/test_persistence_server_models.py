
import persistence.server.models as models
import pytest
import responses

from test_api_workspaced_base import GenericAPITest

from test_cases.factories import ServiceFactory, CommandFactory, \
    CommandObjectFactory, HostFactory, EmptyCommandFactory, \
    UserFactory, VulnerabilityWebFactory, VulnerabilityFactory, \
    ReferenceFactory, PolicyViolationFactory

@pytest.mark.usefixtures('logged_user')
class TestModelsFuncions(GenericAPITest):

    factory = VulnerabilityFactory

    def setUp(self):
        pass

    @responses.activate
    def test_persistence_server_update_vuln(self):

        fo = self.first_object

        vuln = {}
        vuln['desc'] = fo.description
        vuln['data'] = fo.data
        vuln['severity'] = fo.severity
        vuln['refs'] = list(fo.references)
        vuln['confirmed'] = fo.confirmed
        vuln['resolution'] = fo.resolution
        vuln['status'] = fo.status
        vuln['policyviolations'] = list(fo.policy_violations)

        v = models.Vuln(vuln, self.workspace.name)
        v.id = fo.id

        responses.add(responses.PUT, 'http://localhost:5985/_api/v2/ws/{0}/vulns/{1}/'.format(self.workspace.name, v.id),
                      json={}, status=200)

        models.update_vuln(self.workspace.name, v)


