import os
import pytest
from server.models import File
from depot.manager import DepotManager

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def depotfile():
    depot = DepotManager.get('default')
    path = os.path.join(CURRENT_PATH, '../data', 'faraday.png')
    with open(path) as fp:
        fileid = depot.create(fp, 'faraday.png', 'image/png')
    return fileid


@pytest.mark.usefixtures('app')  # To load depot config
def test_get_vulnweb_evidence(vulnerability_web_factory, depotfile, session):
    # Use vuln web to ensure its parent is a service and not a host
    all_vulns = vulnerability_web_factory.create_batch(10)
    session.commit()
    vuln = all_vulns[0]

    correct_file = File(filename='faraday.png', object_id=vuln.id,
                        object_type='vulnerability', content=depotfile)
    session.add(File(filename='faraday.png',
                     object_id=vuln.service_id,
                     object_type='service', content=depotfile))
    session.add(correct_file)

    for other_vuln in all_vulns[1:]:
        session.add(File(filename='faraday.png', object_id=other_vuln.id,
                         object_type='vulnerability', content=depotfile))
        session.add(File(filename='faraday.png',
                         object_id=other_vuln.service_id,
                         object_type='service', content=depotfile))

    session.commit()
    assert vuln.evidence == [correct_file]


@pytest.mark.skip(reason='write to instrumentedlist not implemented')
@pytest.mark.usefixtures('app')  # To load depot config
def test_add_vulnweb_evidence(vulnerability_web, depotfile, session):
    session.commit()
    file_ = File(filename='faraday.png', content=depotfile)
    vulnerability_web.evidence.append(file_)
    session.commit()
    assert len(vulnerability_web.evidence) == 1
    assert vulnerability_web.evidence[0].object_type == 'vulnerability'
    assert vulnerability_web.evidence[0].object_id == vulnerability_web.id
