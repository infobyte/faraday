#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import time
import signal

                                    
from auth.manager import SecurityManager                                                                                       
from auth.manager import codes
from workspace import Workspace
from workspace import WorkspaceManager, WorkspaceOnCouch, WorkspaceOnFS
from shell.controller.env import ShellEnvironment
import model.controller
import model.api
import model.guiapi
import model.log
import traceback
from plugins.managers import PluginManager

                                                                              
from gui.qt3.mainwindow import MainWindow
from utils.error_report import exception_handler
from utils.error_report import installThreadExcepthook
try:
   import qt
except ImportError:
   print "[-] Python QT3 was not found in the system, please install it and try again"
   print "Check the deps file"

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

                                                                                
                                            
                                                 
class MainApplication(object):
    """
    Contains the main QApplication to start the main loop
    The application will handle one workspace at a time.
    The workspace contains the list of hosts discovered
    ShellEnvironments correspond to shell tabs
    ModelController is the bridge between components and discovered
    hosts & services
    
    This class is the principal component, it is responsible for handling
    some events coming from gui and connecting all components together
    """
    
    logger = None
    
    @staticmethod
    def getLogger():
                                    
        if MainApplication.logger is None:
                                             
            MainApplication.logger = model.log.getLogger()
        return MainApplication.logger
    
    def __init__(self):
        self._original_excepthook = sys.excepthook
                                             
        self.qapp = qt.QApplication([])
        self._configuration = CONF                                 
    
                                               
        self._shell_envs = dict()
    
                              
        self._security_manager = SecurityManager()
    
                                        
        self._model_controller = model.controller.ModelController(security_manager = self._security_manager)
        
                                      
                                                         
        self.plugin_manager = PluginManager(os.path.join(CONF.getConfigPath(),"plugins"))
        
        self._workspace_manager = WorkspaceManager(self._model_controller,
                                                   self.plugin_manager.createController("ReportManager"))

        model.guiapi.setMainApp(self)

                                       
        self._main_window = MainWindow(CONF.getAppname(), self, self._model_controller)
        self.qapp.setMainWidget(self._main_window)
    
                                        
                                                                    
        self._splash_screen = qt.QSplashScreen(qt.QPixmap(os.path.join(CONF.getImagePath(),"splash2.png")),
                                               qt.Qt.WStyle_StaysOnTop)
    
                                                                                   
        if not self.getLogger().isGUIOutputRegistered():
                                                 
            self.logger.registerGUIOutput(self._main_window.getLogConsole())
    
                             
        notifier = model.log.getNotifier()
        notifier.widget = self._main_window
    
                                                             
                                
                 
        model.guiapi.setMainApp(self)
        
    def enableExceptHook(self):
        sys.excepthook = exception_handler
        installThreadExcepthook()

    def disableLogin(self):
        CONF.setAuth(sys.disablelogin)
                     
        
    def start(self):
        try:
                                                                         
                                            
                                                                                               
            splash_timer = qt.QTimer.singleShot(1700, lambda *args:None)
            self._splash_screen.show()
        
                                                                                       
            signal.signal(signal.SIGINT, signal.SIG_DFL)
        
            self._writeSplashMessage("Setting up remote API's...")
        
                                 
                                                            
            model.api.setUpAPIs(self._model_controller,CONF.getApiConInfoHost(),CONF.getApiConInfoPort())
            model.guiapi.setUpGUIAPIs(self._model_controller)
        
            self._writeSplashMessage("Starting model controller daemon...")
                                                 
            self._model_controller.start()
        
                                                           
            model.api.startAPIServer()
        
            self._writeSplashMessage("Setting up main GUI...")
        
                                                         
            self._writeSplashMessage("Creating default shell...")
            
            self._main_window.createShellTab()
        
            self._writeSplashMessage("Ready...")
            self.logger.log("Faraday ready...")
        
                                               
            
            self._splash_screen.finish(self._main_window)
            self._main_window.showAll()

                                   
                                           
                                                                     
                  
                                                                     
                                                    
            logged = True
                                                                         
            while True:
                                         
                                                                 
                username, password = "usuario","password"
                                                      
                                                        
                if username is None and password is None:
                    break
                result = self._security_manager.authenticateUser(username, password)
                if result == codes.successfulLogin:
                                                                             
                    logged = True
                    break
        
                                                               
            if logged:
                self._main_window.showLoggedUser(self._security_manager.current_user.display_name)
                model.api.__current_logged_user = username
                
                self._workspace_manager.loadWorkspaces()
                
                last_workspace = CONF.getLastWorkspace()
                w = self._workspace_manager.createWorkspace(last_workspace)
                self._workspace_manager.setActiveWorkspace(w)
                
                                                                 
                                                                           
                self._main_window.getWorkspaceTreeView().loadAllWorkspaces()
                
                                           
                                                           
                                                                           
                self._workspace_manager.startReportManager()
                
        except Exception:
                                                                           
                                                                       
                                        
            print "There was an error while starting Faraday"
            print "-" * 50
            traceback.print_exc()
            print "-" * 50
            self.__exit(-1)
        
        if logged:
                                                                         
            exit_code = self.qapp.exec_loop()
        else:
                                                                  
            exit_code = -1
    
                                
        return self.__exit(exit_code)
    
    def __exit(self, exit_code=0):
        """
        Exits the application with the provided code.
        It also waits until all app threads end.
        """
        self._workspace_manager.stopAutoLoader()
        self._workspace_manager.stopReportManager()

        self._main_window.hide()
        print "Closing Faraday..."
        self._workspace_manager.saveWorkspaces()
        envs = [env for env in self._shell_envs.itervalues()]
        for env in envs:
            env.terminate()                                  
                                  
        print "stopping model controller thread..."
        self._model_controller.stop()
        print "stopping model controller thread..."
        self.qapp.quit()
        print "Waiting for controller threads to end..."
        self._model_controller.join()
                         
        return exit_code
    
    def quit(self):
        """
        Redefined quit handler to nicely end up things
        """
                      
        self.qapp.quit()
    
    def createShellEnvironment(self, name = None):
                                                    
                                         
        model.api.devlog("createShellEnvironment called - About to create new shell env with name %s" % name)
    
        shell_env = ShellEnvironment(name, self.qapp,
                                        self._main_window.getTabManager(),
                                        self._model_controller,
                                        self.plugin_manager.createController,
                                        self.deleteShellEnvironment)
    
        self._shell_envs[name] = shell_env
        self._main_window.addShell(shell_env.widget)
        shell_env.run()
    
    def deleteShellEnvironment(self, name, ref=None):
 
        def _closeShellEnv(name):
            try:
                env = self._shell_envs[name]
                env.terminate()                                  
                tabmanager.removeView(env.widget)
                                                                       
                del self._shell_envs[name]
            except Exception:
                model.api.devlog("ShellEnvironment could not be deleted")
                model.api.devlog("%s" % traceback.format_exc())
 
                                                             
                                                                                           
        model.api.devlog("deleteShellEnvironment called - name = %s - ref = %r" % (name, ref))
        tabmanager = self._main_window.getTabManager()
        if len(self._shell_envs) > 1 :
            _closeShellEnv(name)
        else:
                                                     
                                                   
                                    
            if ref is not None:
                                                                         
                result = self._main_window.exitFaraday()
                if result == qt.QDialog.Accepted:
                    self.quit()
                else:
                                                                 
                                                                            
                    _closeShellEnv(name)
                    self._main_window.createShellTab()
                    
                        
    def getMainWindow(self):
        return self._main_window
    
    def getWorkspaceManager(self):
        return self._workspace_manager

    def removeWorkspace(self, name):
        model.api.log("Removing Workspace: %s" % name) 
        return self.getWorkspaceManager().removeWorkspace(name)
    
    def syncWorkspaces(self):
        try:
            self._workspace_manager.saveWorkspaces()
        except Exception:
            model.api.log("An exception was captured while synchronizing workspaces\n%s"
                          % traceback.format_exc(), "ERROR")
    
    def saveWorkspaces(self):
        try:
            self._workspace_manager.saveWorkspaces()
        except Exception:
            model.api.log("An exception was captured while saving workspaces\n%s"
                          % traceback.format_exc(), "ERROR")
    
    def createWorkspace(self, name, description="", w_type=""):
                                                                 
        if name in self._workspace_manager.getWorkspacesNames():
                                        
            model.api.log("A workspace with name %s already exists"
                          % name, "ERROR")
        else:
            model.api.log("Creating workspace '%s'" % name)
            model.api.devlog("Looking for the delegation class")
            workingClass = globals()[w_type]

            w = self._workspace_manager.createWorkspace(name, description, workspaceClass = workingClass )
            self._workspace_manager.setActiveWorkspace(w)
            self._model_controller.setWorkspace(w)

            self._main_window.refreshWorkspaceTreeView()
                                                                       
            self._main_window.getWorkspaceTreeView().loadAllWorkspaces()
        
    def openWorkspace(self, name):
        self.saveWorkspaces()
        try:
            workspace = self._workspace_manager.openWorkspace(name)
            self._model_controller.setWorkspace(workspace) 
        except Exception:
            model.api.log("An exception was captured while opening workspace %s\n%s"
                          % (name, traceback.format_exc()), "ERROR")

        
    def _writeSplashMessage(self, text):
        self._splash_screen.message(text, qt.Qt.AlignRight | qt.Qt.AlignTop, qt.Qt.red)
    

                                                                                
