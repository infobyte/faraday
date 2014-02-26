#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from gi.repository import Gtk

from gui.gtk.terminal import Terminal


class TabManager(Gtk.Notebook):
    def __init__(self):
        Gtk.Notebook.__init__(self)
        self.n_shells = 0
        self.active_shell_pos = None
        self.shells = []
        self.set_property('show-tabs', True)
        self.create_new_shell()

    def create_new_shell(self):
        terminal = Terminal()
        label = Gtk.Label("Shell-%d" % self.getNextId())
        self.append_page(terminal, label)
        self.active_shell_pos = self.n_shells
        self.n_shells += 1
        self.show_all()

    def getNextId(self):
        return self.n_shells + 1
