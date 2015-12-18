#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import qt
from gui.qt3.toolbars import PerspectiveToolbar
import model.api

class PerspectiveManager(qt.QVBox):

    def __init__(self, parent, main_app):
        qt.QVBox.__init__(self, parent)
        self.setName("PerspectiveManager")
        self.setSpacing(5)
        self.setFrameStyle(qt.QFrame.PopupPanel | qt.QFrame.Plain)
        self._main_app = main_app
        self._active_perspective = None
        self._default = ""
        self._registered = {}
        self._toolbar = PerspectiveToolbar(self, "perspective_toolbar")
        self.setStretchFactor(self._toolbar, 0)
        self._stack_panel = qt.QWidgetStack(self)
        self._stack_panel.setFrameStyle(qt.QFrame.PopupPanel | qt.QFrame.Plain)
        self.setStretchFactor(self._stack_panel, 10)

    def _isValid(self, p):
                                                                     
        return p.parent() == self

    def registerPerspective(self, p, default=False):
        if self._isValid(p):
            self._stack_panel.addWidget(p)                            
            if p.name() not in self._registered:
                self._registered[p.name()] = p
                                                                       
                p.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
                self._toolbar.addPerspective(p.name())
                if default:
                    self._default = p.name()
                    self.setActivePerspective(p.name())

    def getActivePerspective(self):
        return self._active_perspective

    def setActivePerspective(self, name):
        if isinstance(name, int):                                              
            name = self._toolbar.getSelectedValue()

        model.api.devlog("setActivePerspective called - name = " + name)
                                               

        if name in self._registered:
            self._active_perspective = self._registered[name]
            if name == "Workspaces":
                self._active_perspective.loadAllWorkspaces()
            self._stack_panel.raiseWidget(self._active_perspective)

    def showDefaultPerspective(self):
        self.setActivePerspective(self._default)

    def getToolbar(self):
        return self._toolbar

    def sizeHint(self):
        return qt.QSize(70, 0)
        
    def getMainApp(self):
        return self._main_app
