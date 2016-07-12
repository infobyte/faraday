#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

This module is intended to function as a compatibility layer to support both
GObject Instrospection 3.12, 3.16 and 3.20 (Ubuntu 14.04, Brew on Mac OS and
Arch, respectively) and VTE API 2.90 and 2.91 (Ubuntu 14.04 has 2.90, last one
is 2.91)
'''

import gi
gi_version = gi.__version__

gi.require_version('Gtk', '3.0')
try:
    gi.require_version('Vte', '2.91')
    vte_version = '2.91'
except ValueError:
    gi.require_version('Vte', '2.90')
    vte_version = '2.90'

from gi.repository import Vte, Gtk

class CompatibleVteTerminal(Vte.Terminal):
    """A simple VTE terminal modified to be compatible with both 2.90
    and 2.91 API"""
    def __init__(self):
        Vte.Terminal.__init__(self)

    def spawn_sync(self, pty_flags, working_directory, argument_vector,
                   env_variables, glib_spawn_flags, child_setup,
                   child_setup_data, cancellable=None):
        """Returns the corresponden version os 'spawn_sync' method
        according to the Vte version the user has"""
        if vte_version == '2.91':
            return Vte.Terminal.spawn_sync(self, pty_flags, working_directory,
                                           argument_vector, env_variables,
                                           glib_spawn_flags, child_setup,
                                           child_setup_data, cancellable)
        elif vte_version == '2.90':
            return Vte.Terminal.fork_command_full(self, pty_flags,
                                                  working_directory,
                                                  argument_vector, env_variables,
                                                  glib_spawn_flags, child_setup,
                                                  child_setup_data, cancellable)

class CompatibleScrolledWindow(Gtk.ScrolledWindow):
    """A simple Gtk.ScrolledWindow, replacing set_overlay_scrolling for None
    if Gobject Instrospection is too old."""
    def __init__(self, *args, **kwargs):
        Gtk.ScrolledWindow.__init__(self, *args, **kwargs)

    @staticmethod
    def new(hadjustment, vadjustment):
        return Gtk.ScrolledWindow.new(hadjustment, vadjustment)

    def set_overlay_scrolling(self, boolean):
        """Return the set_overlay_scrolling method, if it can."""
        if gi_version == '3.12.0':
            return None
        else:
            return Gtk.ScrolledWindow.set_overlay_scrolling(self, boolean)




