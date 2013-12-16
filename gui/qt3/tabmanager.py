'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import qt
import os
import model.api as api
from model.guiapi import getMainWindow

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

#TODO: define some way to rename each tab

#TODO: check if we should reimplement our own QTabBar and replace the one on this
# QTabWidget

#TODO: check if the PYSIGNAL contextMenu needs to be changed because it is also
# used in the gui.hostbrowser

class ContextMenuTabBar(qt.QTabBar):
    def __init__(self, parent):
        qt.QTabBar.__init__(self,parent)
        self._actions = {}
        self._setupActions()
        self.connect(self, qt.PYSIGNAL('contextMenu'), self._showContextMenu )
        self.contextPopupMenu = qt.QPopupMenu(self)
        self._setupContextPopupMenu()
       
    def addAction(self, name, func):
        self._actions[name] = func

    def _setupContextPopupMenu(self):
        """
        setups all items in the context menu with all its actions
        """
        #insertItem ( const QString & text,
        #              const QObject * receiver,
        #              const char * member,
        #              const QKeySequence & accel = 0,
        #              int id = -1,
        #              int index = -1 )
        self.contextPopupMenu.insertItem("Allow plugins on this shell", self._allowPlugins)
        self._actions["new_shell"].addTo(self.contextPopupMenu);
        self._actions["close_shell"].addTo(self.contextPopupMenu);
        #self.contextPopupMenu.insertItem("Close tab", self._actions["close_shell"])

    def contextMenuEvent(self, event):
        #XXX: emits the signal to show the parent context menu
        # this will end up calling the TreeView _showContextMenu
        self.emit( qt.PYSIGNAL('contextMenu'), (event.globalPos(),) )

    def _showContextMenu(self, pos):
        """Pop up a context menu when the tab is clicked"""
        self.contextPopupMenu.exec_loop(pos)

    def _allowPlugins(self):
        api.devlog("<TabManager> plugins are allowed for current shell (%s)" % self.parent().activeWindow())

    def mouseDoubleClickEvent (self, ev):
        # e is a qt.QMouseEvent
        if "maximize" in self._actions:
            self._actions["maximize"]()
            
    def _setupActions(self):
        """
        creates some actions needed on some menues and toolbars
        """
        a = self._actions["close_shell"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"newshell.png"))), "&Close Shell", qt.Qt.CTRL + qt.Qt.Key_W, self, "New Shell" )
        self.connect(a, qt.SIGNAL('activated()'), self.destroyShellTab)
        
        a = self._actions["new_shell"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"newshell.png"))), "&New Shell", qt.Qt.CTRL + qt.Qt.Key_T, self, "New Shell" )
        self.connect(a, qt.SIGNAL('activated()'), self.createShellTab)

    def destroyShellTab(self):
        getMainWindow().destroyShellTab()
    
    def createShellTab(self):
        getMainWindow().createShellTab()

class TabManager(qt.QTabWidget):

    def __init__(self, parent):
        qt.QTabWidget.__init__(self, parent)
        self.views = []
        self.setMargin(10)
        self.connect(self, qt.SIGNAL('currentChanged(QWidget*)'), self._setFocus)
        
        # we replace the tab bar with our own wich handles contextMenu
        tabbar = ContextMenuTabBar(self)
        self.setTabBar(tabbar)
        self._next_id = 0
    
    def getNextId(self):
        self._next_id += 1
        return self._next_id
        
    def addView(self, view):
        if view not in self.views:
            self.views.append(view)
            self.addTab(view, view.name())
            self.showPage(view)

    def removeView(self, view):
        if view in self.views:
            self.views.remove(view)
            self.removePage(view)

    def activeWindow(self):
        return self.currentPage()

    def windowList(self):
        return self.views

    def cascade(self): pass

    def tile(self): pass

    def canCascade(self):
        return False

    def canTile(self):
        return False

    def count(self):
        return len(self.views)

    def _setFocus(self, widget):
        # just set focus is set on the widget that is contained in the new selected page.
        widget.setFocus()