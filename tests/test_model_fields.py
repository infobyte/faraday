'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from pathlib import Path

from faraday.server.fields import FaradayUploadedFile

TEST_DATA_PATH = Path(__file__).parent / 'data'


def test_html_content_type_is_not_html():
    with open(TEST_DATA_PATH / 'test.html', "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1


def test_image_is_detected_correctly():

    with open(TEST_DATA_PATH / 'faraday.png', "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'image/png'
        assert 'thumb_id' in field.keys()
        assert 'thumb_path' in field.keys()
        assert len(field['files']) == 2


def test_normal_attach_is_not_detected_as_image():
    with open(TEST_DATA_PATH / 'report_w3af.xml', "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1
