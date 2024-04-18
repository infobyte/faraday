"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (https://faradaysec.com/)
See the file 'doc/LICENSE' for the license information
"""
# Standard library imports
import imghdr
import json
from tempfile import SpooledTemporaryFile

# Related third party imports
import flask
import sqlalchemy as sa
from depot.fields.upload import UploadedFile
from depot.io.utils import file_from_content, INMEMORY_FILESIZE
from depot.manager import DepotManager
from PIL import Image
from sqlalchemy.dialects.postgresql.json import JSONB
from webargs.core import ValidationError


class FaradayUploadedFile(UploadedFile):
    """Simple :class:`depot.fields.interfaces.DepotFileInfo` implementation that stores files.

    Takes a file as content and uploads it to the depot while saving around
    most file information. Pay attention that if the file gets replaced
    through depot manually the ``UploadedFile`` will continue to have the old data.

    Also provides support for encoding/decoding using JSON for storage inside
    databases as a plain string.

    Default attributes provided for all ``UploadedFile`` include:
        - filename     - This is the name of the uploaded file
        - file_id      - This is the ID of the uploaded file
        - path         - This is a depot_name/file_id path which can
                         be used with :meth:`DepotManager.get_file` to retrieve the file
        - content_type - This is the content type of the uploaded file
        - uploaded_at  - This is the upload date in YYYY-MM-DD HH:MM:SS format
        - url          - Public url of the uploaded file
        - file         - The :class:`depot.io.interfaces.StoredFile` instance of the stored file
    """
    max_size = 1024
    thumbnail_format = 'PNG'
    thumbnail_size = (128, 128)

    def process_content(self, content, filename=None, content_type=None):
        if isinstance(content, str):
            content = content.encode('utf-8')
        image_format = imghdr.what(None, h=content[:32])
        if image_format:
            content_type = f'image/{image_format}'
            self.generate_thumbnail(content)
        return super().process_content(
                content, filename, content_type)

    def generate_thumbnail(self, content):
        content = file_from_content(content)
        uploaded_image = None
        try:
            uploaded_image = Image.open(content)
        except ValidationError:
            flask.abort(400, ValidationError(
                {
                    'message': 'File Format',
                    'object': {"error": "Format Incorrect"},
                }
            ))
        if max(uploaded_image.size) >= self.max_size:
            uploaded_image.thumbnail((self.max_size, self.max_size), Image.BILINEAR)
            content = SpooledTemporaryFile(INMEMORY_FILESIZE)
            uploaded_image.save(content, uploaded_image.format)

        content.seek(0)

        thumbnail = uploaded_image.copy()
        thumbnail.thumbnail(self.thumbnail_size, Image.LANCZOS)
        thumbnail = thumbnail.convert('RGBA')
        thumbnail.format = self.thumbnail_format

        output = SpooledTemporaryFile(INMEMORY_FILESIZE)
        thumbnail.save(output, self.thumbnail_format)
        output.seek(0)

        thumb_path, thumb_id = self.store_content(output, f'thumb.{self.thumbnail_format.lower()}')
        self['thumb_id'] = thumb_id
        self['thumb_path'] = thumb_path

        thumbnail_file = self.thumb_file
        self['_thumb_public_url'] = thumbnail_file.public_url
        content.close()

    @property
    def thumb_file(self):
        return self.depot.get(self.thumb_id)

    @property
    def thumb_url(self):
        public_url = self['_thumb_public_url']
        if public_url:
            return public_url
        return DepotManager.get_middleware().url_for(self['thumb_path'])


class JSONType(sa.types.TypeDecorator):
    impl = sa.UnicodeText

    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(JSONB())
        else:
            return dialect.type_descriptor(self.impl)

    def process_bind_param(self, value, dialect):
        if dialect.name == 'postgresql':
            return value
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if dialect.name == 'postgresql':
            return value
        if value is not None:
            value = json.loads(value)
        return value
