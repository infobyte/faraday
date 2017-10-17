import imghdr
from tempfile import SpooledTemporaryFile

from PIL import Image

from depot.fields.upload import UploadedFile
from depot.io.utils import file_from_content
from depot.io.utils import INMEMORY_FILESIZE
from depot.manager import DepotManager


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
    forbidden_content_types = [
        'text/html',
        'application/javascript',
    ]

    def process_content(self, content, filename=None, content_type=None):
        """Standard implementation of :meth:`.DepotFileInfo.process_content`

        This is the standard depot implementation of files upload, it will
        store the file on the default depot and will provide the standard
        attributes.

        Subclasses will need to call this method to ensure the standard
        set of attributes is provided.
        """

        file_path, file_id = self.store_content(content, filename, content_type)

        self['file_id'] = file_id

        saved_file = self.file
        self['content_type'] = saved_file.content_type
        if any(map(lambda forbidden_content_type: self['content_type'] in forbidden_content_type, self.forbidden_content_types)):
            raise UserWarning('Content not allowed')
        self['filename'] = saved_file.filename

        self['path'] = file_path
        self['uploaded_at'] = saved_file.last_modified.strftime('%Y-%m-%d %H:%M:%S')
        self['_public_url'] = saved_file.public_url

        image_format = imghdr.what(None, h=content[:32])
        if image_format:
            self['content_type'] = 'image/{0}'.format(image_format)
            self.generate_thumbnail(content)

    def generate_thumbnail(self, content):
        content = file_from_content(content)
        uploaded_image = Image.open(content)
        if max(uploaded_image.size) >= self.max_size:
            uploaded_image.thumbnail((self.max_size, self.max_size), Image.BILINEAR)
            content = SpooledTemporaryFile(INMEMORY_FILESIZE)
            uploaded_image.save(content, uploaded_image.format)

        content.seek(0)

        thumbnail = uploaded_image.copy()
        thumbnail.thumbnail(self.thumbnail_size, Image.ANTIALIAS)
        thumbnail = thumbnail.convert('RGBA')
        thumbnail.format = self.thumbnail_format

        output = SpooledTemporaryFile(INMEMORY_FILESIZE)
        thumbnail.save(output, self.thumbnail_format)
        output.seek(0)

        thumb_path, thumb_id = self.store_content(output,
                                                  'thumb.%s' % self.thumbnail_format.lower())
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
