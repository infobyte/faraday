#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from gui.gui_app import FaradayUi
from gi.repository import Gtk
from gui.gtk.mainwindow import MainWindow


class GuiApp(Gtk.Application, FaradayUi):
    def __init__(self, model_controller, plugin_manager, workspace_manager):
        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager)
        Gtk.Application.__init__(self)

    def do_activate(self):
        self.main_window = MainWindow(self)

    def do_startup(self):
        Gtk.Application.do_startup(self)

    def quit(self):
        self.main_window.hide()
