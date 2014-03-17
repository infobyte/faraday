#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from gi.repository import Gtk
from gui.gtk.mainwindow import MainWindow


class GuiApp(Gtk.Application):
    def __init__(self, model_controller):
        Gtk.Application.__init__(self)

    def do_activate(self):
        self.main_window = MainWindow(self)

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def setSplashImage(self, ipath):
        pass

    def startSplashScreen(self):
        pass

    def stopSplashScreen(self):
        pass

    def quit(self):
        self.main_window.hide()

    def loadWorkspaces(self):
        pass
