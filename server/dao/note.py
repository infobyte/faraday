# Faraday Penetration Test IDE
# Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
# See the file 'doc/LICENSE' for the license information

from sqlalchemy.sql import func
from server.dao.base import FaradayDAO
from server.models import Note


class NoteDAO(FaradayDAO):
    MAPPED_ENTITY = Note

    def count(self, group_by=None):
        total_count = self._session.query(func.count(Note.id)).scalar()
        return { 'total_count': total_count }

