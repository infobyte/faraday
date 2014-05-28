'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from utils.logs import getLogger
from gui.customevents import CHANGEFROMINSTANCE


class EventWatcher(object):
    def __init__(self):
        self.logger = getLogger()

    def update(self, event):
        if event.type() == CHANGEFROMINSTANCE:
            self.logger.info("[Update Received] " + event.change.getMessage())
