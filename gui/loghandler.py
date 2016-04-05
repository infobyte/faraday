'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import logging
import threading
import model.guiapi
from gui.customevents import LogCustomEvent

class GUIHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self._widgets = []
        self._widgets_lock = threading.RLock()
        formatter = logging.Formatter(
            '%(levelname)s - %(asctime)s - %(name)s - %(message)s')
        self.setFormatter(formatter)

    def registerGUIOutput(self, widget):
        self._widgets_lock.acquire()
        self._widgets.append(widget)
        self._widgets_lock.release()

    def clearWidgets(self):
        self._widgets_lock.acquire()
        self._widgets = []
        self._widgets_lock.release()

    def emit(self, record):
        try:
            msg = self.format(record)
            self._widgets_lock.acquire()
            for widget in self._widgets:
                event = LogCustomEvent(msg)
                model.guiapi.postCustomEvent(event, widget)
            self._widgets_lock.release()
        except:
            self.handleError(record)
