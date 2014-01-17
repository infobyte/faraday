'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import qt
from gui.qt3.pyqonsole.widget import ShellWidget
from gui.qt3.tabmanager import TabManager
from gui.qt3.perspective import PerspectiveManager
from gui.qt3.hostsbrowser import HostsBrowser
from gui.qt3.workspacebrowser import WorkspaceTreeWindow
from gui.qt3.dialogs import *
                                       
                                        
                                        
                                            
                                         
                                                 
                                              
                                                   
                                       
                                               
from gui.qt3.configdialog import ConfigDialog
from gui.qt3.toolbars import *
from gui.qt3.customevents import *
from model.workspace import CouchdbManager


import model.api
import webbrowser
sys.path.append("./dependencies/jit")
import subprocess
import datetime
import threading
import time

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

                                    
test_count = 0

                                                                                

class MainWindow(qt.QMainWindow):

    def __init__(self, title, main_app, model_controller):
        qt.QMainWindow.__init__(self, None, title, qt.Qt.WDestructiveClose)
        self.setWindowState(qt.Qt.WindowMaximized)
        self.setCaption(title)


                              
        self.setIcon(qt.QPixmap(os.path.join(CONF.getIconsPath(),"faraday_icon.png")))

                                                                                 
        self._main_app = main_app
        self._model_controller = model_controller

        self._mainArea = qt.QHBox(self)
        self.setCentralWidget(self._mainArea)
        self._vb_splitter = qt.QSplitter(self._mainArea)
        self._vb_splitter.setOrientation(qt.QSplitter.Vertical)
                                                         
        self._hb_splitter = qt.QSplitter(self._vb_splitter)
        self._hb_splitter.setOrientation(qt.QSplitter.Horizontal)
                                                          
                                                                            
                                          

        self.statusBar().setSizeGripEnabled(False)

        self._shell_widgets = []

                                  
                                                                               
                                         
        self._tab_manager = TabManager(self._hb_splitter)
        self._perspective_manager = PerspectiveManager(self._hb_splitter, self._main_app)

                        
        self._hosts_treeview = HostsBrowser(self._perspective_manager,"Hosts")
        self._model_controller.registerWidget(self._hosts_treeview)
        self._perspective_manager.registerPerspective(self._hosts_treeview, default=True)
        
                                                                        
        wtw = WorkspaceTreeWindow(self._perspective_manager, "Workspaces",
                                  self._main_app.getWorkspaceManager())
        self._perspective_manager.registerPerspective(wtw)
        self._workspaces_treeview = wtw

        self._log_console = LogConsole(self._vb_splitter,"Console")

                                         
        self._actions = dict()
        self._setupActions()

                              
        self._menues = {}
        self._setupMenues()

                  
        self.main_toolbar = qt.QToolBar(self,'main toolbar')
        self._setupMainToolbar()

        self.location_toolbar = LocationToolbar(self,'location toolbar')
        self.location_toolbar.setOffset(1500)
                                     

                                    
        self._status_bar_widgets = dict()
        self._setupStatusBar()

        self._is_shell_maximized = False

                    
        self.shell_font=qt.QFont()
        self.shell_font.setRawName(CONF.getFont())
        self.setSizeFont()
        
    def setSizeFont(self):
        if re.search("fixed",str(self.shell_font.family()),re.IGNORECASE) is None:
            self.shell_font=qt.QFont()
            CONF.setFont("-Misc-Fixed-medium-r-normal-*-12-100-100-100-c-70-iso8859-1")
            CONF.saveConfig()
            self.shell_font.setRawName(CONF.getFont())

        self._sizes = [6,7,8,9,10,11,12,14,16,18,20,22,24,26,28,36]
        i=0
        self._size=6
        for f_i in self._sizes:
            if f_i == self.shell_font.pixelSize():
                self._size=i
            i+=1
        

    def setMainApp(self, mainapp):
        self._main_app = mainapp


    def _setupActions(self):
        """
        creates some actions needed on some menues and toolbars
        Actions are later added to different toolbars, for example in
        method _setupMainToolbar
        """
                 
                         
        a = self._actions["new_shell"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"newshell.png"))), "&New Shell", qt.Qt.CTRL + qt.Qt.SHIFT + qt.Qt.Key_T, self, "New Shell" )
        self.connect(a, qt.SIGNAL('activated()'), self.createShellTab)

                   
        a = self._actions["close_shell"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"exit.png"))), "&Close Shell", qt.Qt.CTRL + qt.Qt.SHIFT +qt.Qt.Key_W, self, "New Shell" )
        self.connect(a, qt.SIGNAL('activated()'), self.destroyShellTab)

                          
        a = self._actions["toggle-hosttree"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"HostTreeView.png"))), "Toggle Host Tree", 0, self, "Toggle Log Console" )
        a.setToggleAction(True)
        a.toggle()                                                               
        self.connect(a, qt.SIGNAL('activated()'), self.togglePerspectives)

                        
        a = self._actions["toggle-logconsole"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"LogConsole.png"))), "Toggle Log Console", 0, self, "Toggle Log Console" )
        a.setToggleAction(True)
        a.toggle()                                                             
        self.connect(a, qt.SIGNAL('activated()'), self.toggleLogConsole)

                               
        a = self._actions["maximize-shell"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"maximize.png"))), "Maximize Shell", 0, self, "Maximize Shell" )
        a.setToggleAction(True)
                                                                                
        self.connect(a, qt.SIGNAL('activated()'), self.maximizeShell)
        self._tab_manager.tabBar().addAction("maximize", self.maximizeShell)

                                  
                                                                                                                                                                                
                                
                                                                                
                                                                        
                                                                                        

                     
        a = self._actions["test"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"donotpresstheredbutton.png"))), "Test", qt.Qt.CTRL + qt.Qt.Key_H, self, "Test" )
                                                                
        self.connect(a, qt.SIGNAL('activated()'), self.test)

        a = self._actions["screenshot"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"Screenshot.png"))), "Take Screenshot", 0, self, "Take Screenshot" )
        self.connect(a, qt.SIGNAL('activated()'), self.takeScreenshot)

                         
        a = self._actions["clear-hosttree"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"clear.png"))), "Clear Host Tree", qt.Qt.CTRL + qt.Qt.Key_R, self, "Clear Host Tree" )
        self.connect(a, qt.SIGNAL('activated()'), self._hosts_treeview.clearTree)

        
                           
        a = self._actions["repo-config"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"connect.png"))), "Server Connection", 0, self, "Server Connection" )
        self.connect(a, qt.SIGNAL('activated()'), self._showRepositoryConfigDialog)

                                  
        a = self._actions["visualization"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"visualize.png"))), "Visualize", 0, self, "Visualize" )
        self.connect(a, qt.SIGNAL('activated()'), self.runVisualization)

        a = self._actions["plugin"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"config.png"))), "Plugin", 0, self, "Plugin" )
        self.connect(a, qt.SIGNAL('activated()'), self.showPluginSettingsDialog)

                       
        a = self._actions["documentation"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"Documentation.png"))), "Documentation", 0, self, "Documentation" )
        self.connect(a, qt.SIGNAL('activated()'), self.go2Website)

                      
        a = self._actions["exit-faraday"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"exit.png"))), "Exit Faraday", 0, self, "Exit Faraday" )
        self.connect(a, qt.SIGNAL('activated()'), self.exitFaraday)
        
                               
                                                                                                                                                                          
                                                                       
        
                          
        a = self._actions["create-workspace"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"sync.png"))), "Create", 0, self, "Create" )
        self.connect(a, qt.SIGNAL('activated()'), self.createWorkspace)
        
                        
                                                                                                                                                            
                                                                       
        
                        
        # a = self._actions["open-workspace"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"sync.png"))), "Open", 0, self, "Open" )
        # self.connect(a, qt.SIGNAL('activated()'), self.openWorkspace)

                        
        a = self._actions["reconnect"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"sync.png"))), "Reconnect", 0, self, "Reconnect" )

        self.connect(a, qt.SIGNAL('activated()'), self.reconnect)

        a = self._actions["bfont"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"fontb.png"))), "Big Font", 0, self, "Big Font" )
        self.connect(a, qt.SIGNAL('activated()'), self.setBfont)

        a = self._actions["sfont"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"fonts.png"))), "Small Font", 0, self, "Small Font" )
        self.connect(a, qt.SIGNAL('activated()'), self.setSfont)
                      
        if CONF.getDebugStatus():
            a = self._actions["debug"] = qt.QAction( qt.QIconSet(qt.QPixmap(os.path.join(CONF.getIconsPath(),"debug.png"))), "Debug", 0, self, "Debug" )
            self.connect(a, qt.SIGNAL('activated()'), self.doDebug)


    def _setupStatusBar(self):
        label_order = ["username", "userLevel", "space", "status"]
        for lname in label_order:
            l = qt.QLabel("", self)
            l.setFrameStyle(qt.QFrame.MenuBarPanel | qt.QFrame.Plain)
            self._status_bar_widgets[lname] = l
            self.statusBar().addWidget(l, 0, True)
                                                                                         
        w = qt.QWidget(self)
        self.statusBar().addWidget(w, 1, True)

    def _setupMenues(self):
        """
        Configures all the main windows menues
        """
                                                                                         
                          
        self._menues["file"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&File',self._menues["file"])
                                                                   
                                                                    
                                                                     
        
                                                               
                                                                          
                                                                          
        self._actions["exit-faraday"].addTo(self._menues["file"]);
        self.menuBar().insertSeparator()

                          
        self._menues["shell"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&Shell',self._menues["shell"])
        self._actions["new_shell"].addTo(self._menues["shell"]);
        self._actions["close_shell"].addTo(self._menues["shell"]);
        self._actions["maximize-shell"].addTo(self._menues["shell"]);
                                                                         
        self.menuBar().insertSeparator()
                          
        self._menues["edit"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&Edit',self._menues["edit"])
        self._menues["edit"].insertItem('&Copy', self._copy)
        self._menues["edit"].insertItem('&Paste', self._paste)
                                                                                
        self._actions["repo-config"].addTo(self._menues["edit"]);
                                          
        self.menuBar().insertSeparator()

                               
        self._menues["workspace"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&Workspace',self._menues["workspace"])
        # self._actions["open-workspace"].addTo(self._menues["workspace"])
        self._actions["create-workspace"].addTo(self._menues["workspace"])
                                                                          
                                                                          
                                               
        self.menuBar().insertSeparator()

                           
        self._menues["tools"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&Tools',self._menues["tools"])
        self._actions["visualization"].addTo(self._menues["tools"]);
                                                                                     
        self._actions["plugin"].addTo(self._menues["tools"]);
        self._actions["screenshot"].addTo(self._menues["tools"]);
                                                                                          
        self.menuBar().insertSeparator()

                          
        self._menues["view"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&View',self._menues["view"])
        self._actions["toggle-hosttree"].addTo(self._menues["view"]);
        self._actions["toggle-logconsole"].addTo(self._menues["view"]);
        self._actions["maximize-shell"].addTo(self._menues["view"]);
                                          
        self.menuBar().insertSeparator()

                          
        self._menues["help"] = qt.QPopupMenu(self)
        self.menuBar().insertItem('&Help',self._menues["help"])
        self._menues["help"].insertItem('&About', self._showAboutDialog)
        self._actions["documentation"].addTo(self._menues["help"]);
                                         

                                             
                                                                      
    def _setupMainToolbar(self):
        """
        Sets up the main toolbar
        """
        self._actions["new_shell"].addTo(self.main_toolbar)
        self._actions["toggle-hosttree"].addTo(self.main_toolbar)
        self._actions["toggle-logconsole"].addTo(self.main_toolbar)
        self._actions["maximize-shell"].addTo(self.main_toolbar)
                                                       
        self._actions["clear-hosttree"].addTo(self.main_toolbar)
        self._actions["repo-config"].addTo(self.main_toolbar)
        self._actions["visualization"].addTo(self.main_toolbar)
        self._actions["plugin"].addTo(self.main_toolbar)
        self._actions["screenshot"].addTo(self.main_toolbar)
        self._actions["reconnect"].addTo(self.main_toolbar)
        self._actions["sfont"].addTo(self.main_toolbar)
        self._actions["bfont"].addTo(self.main_toolbar)
        if CONF.getDebugStatus():
            self._actions["debug"].addTo(self.main_toolbar)

    def setFilter(self):
        value = self.location_toolbar.getSelectedValue()
        self._hosts_treeview.filterTree(value)
        self.location_toolbar.addFilter(value)

    def showAll(self):
                                       
        self.show()
                       
        self.main_toolbar.show()
        self.location_toolbar.show()
                                     
        self._tab_manager.show()

        self._perspective_manager.show()

                                    
        self._hosts_treeview.show()
                                
        self._log_console.show()
                                
        for shell_widget in self._shell_widgets:
            shell_widget.show()

    def addShell(self, shell_widget):
        self._shell_widgets.append(shell_widget)
                                                       
                                                
        self._tab_manager.addView(shell_widget)
        shell_widget.show()
        shell_widget.setFocus()

    def createShellTab(self):
                                                         
        tab_name = "Shell-%d" % self._tab_manager.getNextId()
        self._main_app.createShellEnvironment(tab_name)

    def destroyShellTab(self):
                                                              
                                  
        tabmanager = self.getTabManager()
        if tabmanager.count() == 1:
            self.exitFaraday()
        else:
            index = tabmanager.currentPageIndex()
            name = tabmanager.label(index)
            self._main_app.deleteShellEnvironment(str(name))
        

    def imIncomplete(self):
        model.api.log("This function is not implemented yet")

    
                                                                            
                                                                   
                                                                       
                                                                                
                                                                               
                           
    
                                                                                               
    def _copy(self):
        None

    def _paste(self):
                      
                                
        text = qt.QApplication.clipboard().text()
        if not text.isEmpty():
            text.replace(qt.QRegExp("\n"), "\r")
        ev = qt.QKeyEvent(qt.QEvent.KeyPress, 0, -1, 0, text)
        shell = self.getShellWithFocus()
        if shell:
            shell.myemit('keyPressedSignal', (ev,))                                     
            shell.myemit('clearSelectionSignal')
        qt.QApplication.clipboard().setSelectionMode(False)

    def _importWorkspace(self):
        model.api.showPopup("Be careful that importing could overwrite existing files", level="Warning")
        wm = self._main_app.getWorkspaceManager()
        mwin = self._main_app.getMainWindow()
            
        filename =  QFileDialog.getOpenFileName(
                    "$HOME/.faraday",
                    "Faraday export file  (*.faraday)",
                    None,
                    "import file dialog",
                    "Choose a file to import" );
        if filename and filename is not None:
            model.api.log("Import function %s/ %s" % (CONF.getPersistencePath(),filename))
            
                                                                                                               
                                                  
            api.importWorskpace("%s/" % CONF.getPersistencePath(), filename)
            
            wm.loadWorkspaces()
            w = wm.getActiveWorkspace()
            wm.setActiveWorkspace(w)                                      
            
                                                          
            mwin.getWorkspaceTreeView().loadAllWorkspaces()

    def _exportWorkspace(self):
        filename =  QFileDialog.getSaveFileName(
                    "/tmp",
                    "Faraday export file  (*.faraday)",
                    None,
                    "save file dialog",
                    "Choose a file to save the export" );
        if filename and filename is not None:
            model.api.log("Export function %s" % filename)
            api.exportWorskpace("%s/" % CONF.getPersistencePath(), "%s.faraday" % filename)
        
        
    def getTabManager(self):
        return self._tab_manager

    def getLogConsole(self):
        return self._log_console
    
    def getHostTreeView(self):
        return self._hosts_treeview 
    
    def getWorkspaceTreeView(self):
        return self._workspaces_treeview
    
    def refreshWorkspaceTreeView(self):
        self._workspaces_treeview.loadAllWorkspaces()
        
    def _showAboutDialog(self):
        about = AboutDialog(self)
        about.exec_loop()

    def _showConfigDialog(self):
        config_dialog = ConfigDialog(self)
        config_dialog.exec_loop()
    
                    
                                                                                                  
                                                                          
                             
    
    def showExceptionDialog(self, text="", callback=None , excection_objects=None):
        exc_dialog = ExceptionDialog(self, text, callback, excection_objects)
        return exc_dialog.exec_loop()

    def showSimpleDialog(self, text, type="Information"):
        dialog = SimpleDialog(self, text, type)
        return dialog.exec_loop()

    def showPluginSettingsDialog(self, type="Information"):
        dialog = PluginSettingsDialog(self, self._main_app.plugin_manager)
        return dialog.exec_loop()

    def showDebugPersistenceDialog(self, text, type="Information"):
        dialog = DebugPersistenceDialog(self)
        return dialog.exec_loop()

    def showPopup(self, text, type="Information"):
        message = "<b>%s:</b>\n%s" % (type, text)
        notification = NotificationWidget(self, message)
        notification.show()
        qt.QTimer.singleShot(4000, notification.closeNotification)

    def doLogin(self, callback=None):
                                                              
                                                                                     
        login_dialog = LoginDialog(self, callback)
        result_code = login_dialog.exec_loop()
                                                           
                                                                         
        if result_code == qt.QDialog.Rejected:
            return None,None
        else:
            return login_dialog.getData()

    def showLoggedUser(self, username):
        self._status_bar_widgets["username"].setText("Logged user: %s" % username)
  
    def _showRepositoryConfigDialog(self):
                                                                            
        repoconfig_dialog = RepositoryConfigDialog(self, CONF.getCouchURI(),
                                                   CONF.getCouchIsReplicated(),
                                                   CONF.getCouchReplics(),
                                                   callback=None) 
        result = repoconfig_dialog.exec_loop()        
        if result == qt.QDialog.Accepted:
            repourl, isReplicated, replics = repoconfig_dialog.getData()
            api.devlog("repourl = %s" % repourl)
            wm = self._main_app.getWorkspaceManager()
            if not CouchdbManager.testCouch(repourl):
                self.showPopup("""
                Repository URL Not valid, check if
                service is available and that connection string is from
                the form: http[s]://hostname:port""")
                repourl, isReplicated, replics = "", False, ""

            CONF.setCouchUri(repourl)
            CONF.setCouchIsReplicated(isReplicated)
            CONF.setCouchReplics(replics)
            CONF.saveConfig()
            

            couchdbmanager = CouchdbManager(repourl)
            wm.setCouchManager(couchdbmanager)

            wm.loadWorkspaces()
            mwin = self._main_app.getMainWindow()
            mwin.getWorkspaceTreeView().loadAllWorkspaces()
            mwin.getWorkspaceTreeView().setDefaultWorkspace()

    def showConflictsDialog(self, local):
        dialog = ResolveConflictsDialog(self, local=local)
        result = dialog.exec_loop()
        return result

    def customEvent(self, event):
        """
        This method is to be able to handle custom events in order
        to show custom dialogs or pop ups
        """
        if event.type() ==  EXCEPTION_ID:
            self.showExceptionDialog(event.text, event.callback, event.exception_objects)
        elif event.type() ==  SHOWDIALOG_ID:
            self.showSimpleDialog(event.text, event.level)
        elif event.type() ==  SHOWPOPUP_ID:
            self.showPopup(event.text, event.level)
        elif event.type() == CONFLICTS_ID:
                                                                  
            self.showConflictsDialog(event.local)
            
                                
                                
                                
    def toggleLogConsole(self):
        if self._log_console.isVisible():
            self._log_console.hide()
        else:
            self._log_console.show()
            if self._is_shell_maximized:
                self._actions["maximize-shell"].toggle()
                self._is_shell_maximized = False

    def togglePerspectives(self):
        if self._perspective_manager.isVisible():
            self._perspective_manager.hide()
        else:
            self._perspective_manager.show()
            if self._is_shell_maximized:
                self._actions["maximize-shell"].toggle()
                self._is_shell_maximized = False

    def maximizeShell(self):
                                       
                                                      
                                                            
        if self._is_shell_maximized:
            self._is_shell_maximized = False
            if not self._log_console.isVisible():
                self.toggleLogConsole()
                self._actions["toggle-logconsole"].toggle()
            if not self._perspective_manager.isVisible():
                self.togglePerspectives()
                self._actions["toggle-hosttree"].toggle()
        else:
            self._is_shell_maximized = True
            if self._log_console.isVisible():
                self.toggleLogConsole()
                self._actions["toggle-logconsole"].toggle()

            if self._hosts_treeview.isVisible():
                self.togglePerspectives()
                self._actions["toggle-hosttree"].toggle()

    def changeShellFont(self):
        preferences_dialog = PreferencesDialog(self)
        if preferences_dialog.exec_loop():
            self.setShellFont()
            CONF.setFont(self.shell_font.rawName())
            CONF.saveConfig()
    
    def setBfont(self):
        if (self._size+1) < len(self._sizes):
            self._size=self._size+1
            self.setShellFont()

    def setSfont(self):
        if (self._size-1) > -1:
            self._size=self._size-1
            self.setShellFont()
            
    def getShellWithFocus(self):
        for shell in self._shell_widgets:
            if shell.hasFocus():
                return shell
        return None

    def setShellFont(self):
        self.shell_font=qt.QFont()
        CONF.setFont("-Misc-Fixed-medium-r-normal-*-"+str(self._sizes[self._size])+"-100-100-100-c-70-iso8859-1")
        CONF.saveConfig()
        self.shell_font.setRawName(CONF.getFont())

        for shell in self._shell_widgets:
            shell.setVTFont(self.shell_font)

    def runVisualization(self):
        """
        runs script that builds the html for visutalizacion and opens a browser
        """

        ret, url = self._main_app.getWorkspaceManager().createVisualizations()
        if ret:
            webbrowser.open_new(url)

                                                                                             
                                                                                   
                                                                                   
                                                                                 

    def go2Website(self):
                                                                                                   
                            
                                                                                                
                                                                               
        webbrowser.open_new("https://www.faradaysec.com")
        model.api.log("Opening faraday's website")

    def closeEvent(self, e):
        result = self.exitFaraday()
        if result == qt.QDialog.Accepted:
            e.accept()

    def exitFaraday(self):
        exit_dialog = ExitDialog(self, self._main_app.quit)
        return exit_dialog.exec_loop()

    def doDebug(self):
        exit_dialog = MessageDialog(self, self.__debug,"Debug", "Faraday use IPython for debuging, please switch to terminal\n where do you execute the framework, use Ctrl+D to exit debug.\nDo you want to continue?" )
        return exit_dialog.exec_loop()
    
    def __debug(self, item=False):
        from utils import ipython_shell
        ipython_shell.embedd(locals(), globals())

    def takeScreenshot(self):
        view = self._tab_manager.activeWindow()
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%s")
        pixmap = qt.QPixmap.grabWidget(view)
        pixmap.save(os.path.join(CONF.getDefaultTempPath(), "shell_capture_%s.png" % ts), "PNG")
        pixmap = qt.QPixmap.grabWidget(self)
        pixmap.save(os.path.join(CONF.getDefaultTempPath(), "fullscreen_capture_%s.png" % ts), "PNG")
        model.api.log("Screenshots taken")

    def syncWorkspaces(self):
                                                                   
                                             
                                                                                
                  
        self._model_controller.syncActiveWorkspace()

    def saveWorkspaces(self):
        """
        Saves workspaces and it is done syncronically so GUI won't respond
        until it finishes saving everything
        """
                                                   
        model.api.log("Saving workspaces...")
        self._main_app.saveWorkspaces()
        model.api.log("Workspaces saved!")
        
    def createWorkspace(self):
                                                                           
        wdialog = WorkspaceCreationDialog(self, callback=self._main_app.createWorkspace)
        wdialog.exec_loop()
        
        
    def openWorkspace(self):
                                                                         
                                           
        name = "Untitled"
        self._main_app.openWorkspace(name)


    def reconnect(self):
        wm = self._main_app.getWorkspaceManager()
        wm.reconnect() 
        
    """
    #XXX: test ALT+r on console to delete line
    def test2(self):
        for env in self._main_app._shell_envs.itervalues():
            env.session.em.sendString("\033r")
    """
    def testAPI(self):
        import model.api
        model.api.createAndAddHost("prueba-host","Windows 7")
        model.api.createAndAddInterface("eth0", mac = "00:00:00:00:00:00",
                 ipv4_address = "10.1.1.1", ipv4_mask = "255.255.0.0",
                 ipv4_gateway = "10.1.1.2", hostname_resolution = "TestHost",
                 hostname="prueba-host")

        h = model.api.newHost("127.0.0.1", "Windows 2003")
        h = model.api.getHost("prueba-host")
        model.api.addHost(h)
        h.name = "Nuevo Nombre"
        model.api.addHost(h, update = True, old_hostname = "prueba-host")


    def test(self):
        """
        DELETE THIS BEFORE RELEASE
        used for internal testing (not correct way but we need to use it like
        this for now)
        """
                                                              
                       
                       
                                                                       
               
        global test_count
        test_count += 1
        model.api.showPopup("Creating test host %d" % test_count)
                                                                     
        from utils.error_report import exception_handler
        
        def raiser():
            sys.excepthook = exception_handler
            time.sleep(3)
            raise Exception("Exception from a secondary thread...")
                                            
                  
                                                                

        from model.hosts import Host
        from model.hosts import Interface
        from model.hosts import Service
        from model.hosts import HostApplication

        self._main_app.getLogger().log("testing..")
        self._main_app.getLogger().log("creating test host %d" % test_count)
        host = Host("TestHost-%d" % test_count, "Windows 2003")
        service = Service( "TestService-%d" % test_count, "TCP", [80,8080], "running")
        interface = Interface("eth%d" % test_count, mac = "00:00:00:00:00:00",
                 ipv4_address = "10.1.1.%d" % test_count, ipv4_mask = "255.255.0.0",
                 ipv4_gateway = "10.1.1.%d" % (test_count+1),
                 hostname_resolution = "TestHost-%d" % test_count)
        app = HostApplication( "AppTest-%d" % test_count, "running", "1.0 beta")

        
        host.addInterface(interface)
        host.addService(service)
        host.addApplication(app)
        interface.addService(service)
        app.addService(service)
        service.addInterface(interface)
        self._model_controller.addHostASYNC(host)


                                                                                
