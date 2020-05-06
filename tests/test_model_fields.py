'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os

from faraday.server.fields import FaradayUploadedFile

CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))


def test_html_content_type_is_not_html():
    with open(os.path.join(CURRENT_PATH, 'data', 'test.html'), "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1


def test_image_is_detected_correctly():

    with open(os.path.join(CURRENT_PATH, 'data', 'faraday.png'), "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'image/png'
        assert 'thumb_id' in field.keys()
        assert 'thumb_path' in field.keys()
        assert len(field['files']) == 2


def test_normal_attach_is_not_detected_as_image():
    with open(os.path.join(CURRENT_PATH, 'data', 'report_w3af.xml'), "rb")as image_data:
        field = FaradayUploadedFile(image_data.read())
        assert field['content_type'] == 'application/octet-stream'
        assert len(field['files']) == 1


# I'm Py3
