# Copyright (c) 2005-2006 LOGILAB S.A. (Paris, FRANCE).
# Copyright (c) 2005-2006 CEA Grenoble
# http://www.logilab.fr/ -- mailto:contact@logilab.fr
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the CECILL license, available at
# http://www.inria.fr/valorisation/logiciels/Licence.CeCILL-V2.pdf
#
"""Provides the Session class. Sessions are combinations of PtyProcess and
Emulation.

The stuff in here does not really belong to the terminal emulation framework. It
serves it's duty by providing a single reference to TEPTy/Emulation pairs. In
fact, it is only there to demonstrate one of the abilities of the framework:
multible sessions.

Based on the konsole code from Lars Doelle.

@author: Lars Doelle
@author: Sylvain Thenault
@copyright: 2003, 2005-2006
@organization: Logilab
@license: CECILL
"""

__revision__ = '$Id: session.py,v 1.13 2006-02-15 10:24:01 alf Exp $'

import os
import qt
import shell.core.signalable as signalable
import shell.core.qt3.pty_ as pty_
import emulation
import emuVt102


class Session(signalable.Signalable, qt.QObject):
    """A Session is a combination of one PTyProcess and one Emulation instances
    """

    SILENCE_TIMEOUT = 10000 # milliseconds

    def __init__(self, gui, pgm, args, term, sessionid='session-1', cwd=None):
        super(Session, self).__init__()
        self.monitor_activity = False
        self._monitor_silence = False # see the property below
        self.master_mode = False
        # FIXME: using the indices here is propably very bad. We should use a
        # persistent reference instead.
        self.schema_no = 0
        self.font_no = 3
        self.app_id = "qonsole"
        self.icon_name = 'openterm'
        self.icon_text = 'qonsole'
        self.state_icon_name = ''
        self.title = ''
        self.user_title = ''
        self.te = gui
        self.pgm = pgm
        self.args = args
        self.term = term
        self.session_id = sessionid
        self.cwd = cwd
        #XXX: IMPORTANT ABOUT USER INPUT AND PROCESS OUPUT
        # PtyProcess in method dataReceived gets the child output
        # in method sendBytes it has the user input
        self.sh = pty_.PtyProcess()
        # Emulation in method sendString also has the user input
        # also check method onKeyPressed to identify when an ENTER key is pressed
        self.em = emuVt102.EmuVt102(self.te)
        self.monitor_timer = qt.QTimer(self)
        self.sh.setSize(self.te.lines, self.te.columns)
        self.sh.myconnect('block_in', self.em.onRcvBlock)
        self.sh.myconnect('done', self.done)
        self.em.myconnect('imageSizeChanged', self.sh.setSize)
        self.em.myconnect('sndBlock', self.sh.sendBytes)
        self.em.myconnect('changeTitle', self.setUserTitle)
        self.em.myconnect('notifySessionState', self.notifySessionState)
        self.connect(self.monitor_timer, qt.SIGNAL('timeout()'), self.monitorTimerDone)

    def __del__(self):
        self.sh.mydisconnect('done', self.done)

    def setMonitorSilence(self, monitor):
        if self._monitor_silence == monitor:
            return
        self._monitor_silence = monitor
        if monitor:
            self.monitor_timer.start(self.SILENCE_TIMEOUT, True)
        else:
            self.monitor_timer.stop()

    def getMonitorSilence(self):
        return self._monitor_silence

    monitor_silence = property(getMonitorSilence, setMonitorSilence)

    def run(self):
        cwd_save = os.getcwd()
        if self.cwd:
            os.chdir(self.cwd)
        self.sh.run(self.pgm, self.args, self.term, True)
        if self.cwd:
            os.chdir(cwd_save)
        # We are reachable via kwrited XXX not needed by pyqonsole ?
        self.sh.setWriteable(False)


    def setUserTitle(self, what, caption):
        """
        what=0 changes title and icon
        what=1 only icon
        what=2 only title
        """
        if what in (0, 2):
            self.user_title = caption
        if what in (0, 1):
            self.icon_text = caption
        self.myemit('updateTitle', ())

    def fullTitle(self):
        if self.user_title:
            return '%s - %s' % (self.user_title, self.title)
        return self.title

    def testAndSetStateIconName(self, newname):
        if (newname != self.state_icon_name):
            self.state_icon_name = newname
            return True
        return False

    def monitorTimerDone(self):
        self.myemit('notifySessionState', (emulation.NOTIFYSILENCE,))
        self.monitor_timer.start(self.SILENCE_TIMEOUT, True)

    def notifySessionState(self, state):
        if state == emulation.NOTIFYACTIVITY:
            if self.monitor_silence:
                self.monitor_timer.stop()
                self.monitor_timer.start(self.SILENCE_TIMEOUT, True)
            if not self.monitor_activity:
                return
        self.myemit('notifySessionState', (state,))

    def done(self, status):
        self.myemit('done', (self, status,))

    def terminate(self):
        self.sh.mydisconnect('done', self.done)
        self.sh.sendBytes("exit\r")

    def sendSignal(self, signal):
        return self.sh.kill(signal)

    def setConnect(self, connected):
        self.em.setConnect(connected)

    def keymap(self):
        return self.em.keymap()

    def setKeymap(self, kn):
        self.em.setKeymap(kn)

    def setHistory(self, history):
        self.em.setHistory(history)

    def history(self):
        return self.em.history()

    def get_shell_ps1(self):
        self.sh.sendBytes("echo $PS1")

    def set_shell_ps1(self, format):
        self.sh.sendBytes("export PS1=\"%s\"\r" % format)
        #self.sh.sendBytes("export PS1=\"\\e[1;32m<[\\u@\\h \\W]>\\$ \\e[m\"\r")
        self.sh.sendBytes("clear\r")

    def updateLastUserInputLine(self):
        """
        this is called when an interactive command finished and
        we want to save the cursor x,y coordinates for future
        user input parsing
        The coordinates are really stored in the emulation
        """
        self.em.updateLastCursorPos(True)
