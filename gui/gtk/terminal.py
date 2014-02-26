#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os

from gi.repository import Vte, GLib
from config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()


class Terminal(Vte.Terminal):
    def __init__(self):
        Vte.Terminal.__init__(self)
        self.fork_command_full(
            Vte.PtyFlags.DEFAULT,  # flags
            os.environ['HOME'],  # working directory
            ["/usr/bin/zsh"],  # argv
            ["ZDOTDIR=%szsh/" % CONF.getConfigPath()],  # envv
            GLib.SpawnFlags.DO_NOT_REAP_CHILD,  # Spawn flags
            None,  # child_setup: an extra child setup function to run in the child just before exec()
            None,  # child_pid: a location to store the child PID
            )
        self.setup_terminal_widget()

    def setup_terminal_widget(self, margin=5):
        '''
        set the expanding policy and the margins
        '''
        self.set_hexpand(True)
        self.set_vexpand(True)
        self.set_margin_top(margin)
        self.set_margin_bottom(margin)
        self.set_margin_right(margin)
        self.set_margin_left(margin)
