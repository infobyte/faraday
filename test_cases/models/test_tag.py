import pytest
from server.models import TagObject


def test_vulnweb_tags(vulnerability_web_factory, tag_factory, session):
    # Use vuln web to ensure its parent is a service and not a host
    all_vulns = vulnerability_web_factory.create_batch(10)
    session.commit()
    vuln = all_vulns[0]

    correct_tags = tag_factory.create_batch(3)
    for tag in correct_tags:
        session.add(TagObject(tag=tag, object_type='vulnerability',
                              object_id=vuln.id))
    session.add(TagObject(tag=tag_factory.create(),
                          object_type='service',
                          object_id=vuln.service_id))
    for other_vuln in all_vulns[5:]:
        session.add(TagObject(tag=correct_tags[1], object_type='vulnerability',
                              object_id=other_vuln.id))
        session.add(TagObject(tag=tag_factory.create(),
                              object_type='vulnerability',
                              object_id=other_vuln.id))

    session.commit()
    assert vuln.tags == set(correct_tags)
