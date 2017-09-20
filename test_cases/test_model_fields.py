import os

import pytest
from depot.manager import DepotManager

from server.fields  import FaradayUploadedFile

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))

@pytest.fixture(scope='module')
def setup_depot(request):
    DepotManager.configure('default', {
        'depot.storage_path': '/home/lcubo/tmp_images'
    })


def test_html_content_type_is_not_html(setup_depot):
    with open(os.path.join(CURRENT_PATH, 'data', 'test.html'))as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1


def test_image_is_detected_correctly(setup_depot):

    with open(os.path.join(CURRENT_PATH, 'data', 'faraday.png'))as image_data:
        field = FaradayUploadedFile(image_data.read())

        print(field)
        assert field['content_type'] == 'image/png'
        assert 'thumb_id' in field.keys()
        assert 'thumb_path' in field.keys()
        assert len(field['files']) == 2


def test_normal_attach_is_not_detected_as_image(setup_depot):
    with open(os.path.join(CURRENT_PATH, 'data', 'report_w3af.xml'))as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1