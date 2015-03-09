'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from utils.logs import getLogger
from gui.customevents import CHANGEFROMINSTANCE


class EventWatcher(object):
    def __init__(self):
        self.logger = getLogger(self)

    def update(self, event):
        if event.type() == CHANGEFROMINSTANCE:
            getLogger(self).info(
                "[Update Received] " + event.change.getMessage())
