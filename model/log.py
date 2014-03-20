#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import threading
import logging
import logging.handlers
from gui.customevents import (LogCustomEvent,
                              ShowPopupCustomEvent,
                              ShowDialogCustomEvent)
#import qt

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

__the_logger = None
__notifier = None


def getLogger():
    global __the_logger
    if __the_logger is None:
        # we create for the first time
        __the_logger = AppLogger()
    return __the_logger


def getNotifier(singleton=True):
    global __notifier
    if singleton:
        if __notifier is None:
            __notifier = Notifier()
        return __notifier
    else:
        return Notifier()


class AppLogger(object):
    """
    a logging facility to show application activity
    possible outputs are log file
    console in a gui
    This is thread safe. It uses an internal lock to make sure
    text is logged sequentially
    """

    levels = {
            "NOTIFICATION":logging.INFO,\
            "INFO":logging.INFO,\
            "WARNING":logging.WARNING,\
            "ERROR":logging.ERROR,\
            "CRITICAL":logging.CRITICAL,\
            "DEBUG":logging.DEBUG \
            }

    def __init__(self, name = CONF.getAppname()):
        # The logger instance.
        self.__logger = logging.getLogger(name)

        # We set the default level, this can be changed at any moment.
        self.__logger.setLevel(logging.DEBUG)

        # The name of the logger object.
        self.__name = name

        # The handler object.
        self.__handler = None

        # These flag will enable/disable the logger for different outputs
        self.__output_file = False
        self.__output_console = True

        # a list of widgets we need to update when new text comes
        self.__gui_output = []

        self.__lock = threading.RLock()


    def setLogFile(self, filename = None, maxsize=0,maxBackup=10, file_mode = 'a'):
        """
        Set a logfile as an output target. If no filename is given, then a
        file with the instance name with the ".log" extension will be created.
        The file rotates when the size is equal or higher than the
        specified maxsize (in bytes) value. If the maxsize value is 0, the file will increase
        indefinitely. The maxBackup value allows to create backups of rotated
        files with the *.log.1, .2, etc. You can define the maximun value of
        backup created files, if the value is zero, then no backup will be performed.
        """

        # Check if the filename is valid.

        if filename is None:
            # If not, then set a default name with the name of the instance.
            self.__handler = logging.handlers.RotatingFileHandler('%s.log' % self.__name, 'a', maxsize,maxBackup)
        else:
            # If the file_mode is not allowed, open with 'append' mode
            if not (file_mode == 'a' or file_mode == 'w'):
                 file_mode = 'a'

            # The user must set a correct path and filename.
            self.__handler = logging.handlers.RotatingFileHandler(filename, file_mode,maxsize,maxBackup)

        # Set the standard formater to the handler. The '-8' parameter in the level name argument
        # is a print format parameter, it means the converted value is left adjusted(-) and that
        # it spans at max 8 positions(8).
        self.__handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)-8s - %(message)s"))

        # Don't forget to add the handler to the logger.
        self.__logger.addHandler(self.__handler)

    def isGUIOutputRegistered(self):
        """
        determines if there is at least one GUI widget registered
        to show logger output
        """
        if self.__gui_output:
            return True
        else:
            return False

    def registerGUIOutput(self, widget):
        """
        adds a reference to a GUI widget we need to update
        """
        # IMPORTANT: the widget MUST implement a method called appendText
        self.__gui_output.append(widget)

    def setLogLevel(self, level):
        self.__logger.setLevel(level)

    def enableLogOutput(self, enable=True):
        self.__output_file = enable

    def enableConsoleOutput(self, enable=True):
        self.__output_console = enable

    def getLogLevel(self):
        """ Get the current log level. """
        return self.__logger.getEffectiveLevel()

    def isFileEnabled(self):
        return self.__output_file

    def isGUIEnabled(self):
        return self.__output_console

    def __notifyGUIConsole(self, msg):
        """
        notifies all GUI widgets registered
        IMPORTANT: the widgets MUST be able to handle a custom event
        """
        for widget in self.__gui_output:
            event = LogCustomEvent(msg)
            widget.update(event)
            #qt.QApplication.postEvent(widget, event)
            #guiapi.postCustomEvent(widget, event)

    def log(self, msg ,level = "INFO"):
        """
        Send a message to the logger with the specified level and format.
        It will redirect the output to the current target.
        The method will automatically filter those messages with a lower
        "loglevel" than the specified.
        It also will attempt to write the arguments by checking the format
        list, if the arguments are incompatible with the format, it WON'T
        log anything else than the message.
        """
        #TODO: we need to format the message to contain a timestamp for the
        # gui output. The file handles this by itself, but for the gui, only a text
        # message arrives
        level = level.upper()
        if level not in self.levels:
            level = "INFO"

        # take lock
        self.__lock.acquire()
        try:
            if self.__handler and self.__output_file:
                self.__logger.log(self.levels.get(level,logging.INFO), msg)
            # Check if the log is being sent to the console
            if self.__output_console:
                self.__notifyGUIConsole("[%s] - %s" % (level, msg))
        finally: # for safety so we don't block anything
            # after doing all release
            self.__lock.release()


class Notifier(object):
    """
    This class is used to show information to the user using dialog boxes or
    little pop ups (like tooltips).
    Also all notifications get logged using the Application Logger
    """
    
    #TODO: change the implementation to send/post custom events to avoid
    # problems with threads like we had before
    def __init__(self):
        self.widget = None

    def _postCustomEvent(self, text, level, customEventClass):
        getLogger().log(text, "NOTIFICATION")
        if self.widget is not None:
            event = customEventClass(text, level)
            widget.update(event)
            #qt.QApplication.postEvent(self.widget, event)

    def showDialog(self, text, level="Information"):
        self._postCustomEvent(text, level, ShowDialogCustomEvent)

    def showPopup(self, text, level="Information"):
        self._postCustomEvent(text, level, ShowPopupCustomEvent)


