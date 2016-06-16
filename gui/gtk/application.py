#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import sys
import threading

try:
    import gi
except ImportError as e:
    print ("You are missing Gobject Instrospection. Please install "
           "version 3.14 or above")
    sys.exit(1)

try:
    gi.require_version('Gtk', '3.0')
    gi.require_version('Vte', '2.91')
except ValueError:
    print ("WARNING: You don't seem to have installed the recommended versions"
           " of GTK and VTE. Check install of VTE 2.91 and GTK+3")

try:
    # there are several imports not needed here, but they're needed in other
    # modules. this just checks for every dependence when starting the app
    from gi.repository import Gio, Gtk, GdkPixbuf, Vte, GLib, GObject, Gdk
except ImportError as e:
    print ("You are missing some of the required dependencies. "
           "Check that you have GTK+3 and Vte installed.")
    sys.exit(1)


import model.guiapi
import model.api
import model.log

from gui.gui_app import FaradayUi
from config.configuration import getInstanceConfiguration
from utils.logs import getLogger
from persistence.persistence_managers import CouchDbManager
from appwindow import AppWindow

from dialogs import PreferenceWindowDialog
from dialogs import NewWorkspaceDialog
from dialogs import PluginOptionsDialog
from dialogs import NotificationsDialog
from dialogs import aboutDialog
from dialogs import helpDialog
from dialogs import ConflictsDialog
from dialogs import HostInfoDialog
from dialogs import errorDialog
from dialogs import ImportantErrorDialog

from mainwidgets import Sidebar
from mainwidgets import WorkspaceSidebar
from mainwidgets import HostsSidebar
from mainwidgets import ConsoleLog
from mainwidgets import Terminal
from mainwidgets import Statusbar

from gui.loghandler import GUIHandler
from utils.logs import addHandler

CONF = getInstanceConfiguration()


class GuiApp(Gtk.Application, FaradayUi):
    """
    Creates the application and has the necesary callbacks to FaradayUi
    Right now handles by itself only the menu, everything is else is
    appWindow's resposibility as far as the UI goes. All logic by the main
    window should be done here. Some of the logic on the dialogs is
    implemented in the dialogs own class.
    """

    def __init__(self, model_controller, plugin_manager, workspace_manager,
                 plugin_controller):

        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager,
                           plugin_controller)

        Gtk.Application.__init__(self, application_id="org.infobyte.faraday",
                                 flags=Gio.ApplicationFlags.FLAGS_NONE)

        self.icons = CONF.getImagePath() + "icons/"
        faraday_icon = self.icons + "faraday_icon.png"
        self.icon = GdkPixbuf.Pixbuf.new_from_file_at_scale(faraday_icon, 16,
                                                            16, False)
        self.window = None
        self.model_controller = model_controller
        self.conflicts = self.model_controller.getConflicts()

    def getMainWindow(self):
        """Returns the main window. This is none only at the
        the startup, the GUI will create one as soon as do_activate() is called
        """
        return self.window

    def updateConflicts(self):
        """Reassings self.conflicts with an updated list of conflicts"""
        self.conflicts = self.model_controller.getConflicts()

    def updateHosts(self):
        """Reassings the value of self.all_hosts to a current one to
        catch workspace changes, new hosts added via plugins or any other
        external interference with out host list"""
        self.all_hosts = self.model_controller.getAllHosts()

    def createWorkspace(self, name, description="", w_type=""):
        """Pretty much copy/pasted from the QT3 GUI.
        Uses the instance of workspace manager passed into __init__ to
        get all the workspaces names and see if they don't clash with
        the one the user wrote. If everything's fine, it saves the new
        workspace and returns True. If something went wrong, return False"""

        if name in self.getWorkspaceManager().getWorkspacesNames():

            model.api.log("A workspace with name %s already exists"
                          % name, "ERROR")
            status = True
        else:
            model.api.log("Creating workspace '%s'" % name)
            model.api.devlog("Looking for the delegation class")
            manager = self.getWorkspaceManager()
            try:
                w = manager.createWorkspace(name, description,
                                            manager.namedTypeToDbType(w_type))
                CONF.setLastWorkspace(w.name)
                CONF.saveConfig()
                status = True
            except Exception as e:
                status = False
                model.guiapi.notification_center.showDialog(str(e))

        return status

    def removeWorkspace(self, button, ws_name):
        """Removes a workspace. If the workspace to be deleted is the one
        selected, it moves you first to the default. The clears and refreshes
        sidebar"""

        model.api.log("Removing Workspace: %s" % ws_name)
        if CONF.getLastWorkspace() == ws_name:
            self.openDefaultWorkspace()
        self.getWorkspaceManager().removeWorkspace(ws_name)
        self.ws_sidebar.clearSidebar()
        self.ws_sidebar.refreshSidebar()

    def do_startup(self):
        """
        GTK calls this method after Gtk.Application.run()
        Creates instances of the sidebar, terminal, console log and
        statusbar to be added to the app window.
        Sets up necesary acttions on menu and toolbar buttons
        Also reads the .xml file from menubar.xml
        """
        Gtk.Application.do_startup(self)  # deep GTK magic

        self.ws_sidebar = WorkspaceSidebar(self.workspace_manager,
                                           self.changeWorkspace,
                                           self.removeWorkspace,
                                           self.on_new_button,
                                           CONF.getLastWorkspace())

        self.updateHosts()
        self.hosts_sidebar = HostsSidebar(self.show_host_info, self.icons)
        default_model = self.hosts_sidebar.create_model(self.all_hosts)
        default_view = self.hosts_sidebar.create_view(default_model)

        self.sidebar = Sidebar(self.ws_sidebar.get_box(),
                               self.hosts_sidebar.get_box())

        host_count, service_count, vuln_count = self.update_counts()

        self.terminal = Terminal(CONF)
        self.console_log = ConsoleLog()
        self.statusbar = Statusbar(self.on_click_notifications,
                                   self.on_click_conflicts,
                                   host_count, service_count, vuln_count)

        self.notificationsModel = Gtk.ListStore(str)

        action = Gio.SimpleAction.new("about", None)
        action.connect("activate", self.on_about)
        self.add_action(action)

        action = Gio.SimpleAction.new("help", None)
        action.connect("activate", self.on_help)
        self.add_action(action)

        action = Gio.SimpleAction.new("quit", None)
        action.connect("activate", self.on_quit)
        self.add_action(action)

        action = Gio.SimpleAction.new("preferences", None)
        action.connect("activate", self.on_preferences)
        self.add_action(action)

        action = Gio.SimpleAction.new("pluginOptions", None)
        action.connect("activate", self.on_pluginOptions)
        self.add_action(action)

        action = Gio.SimpleAction.new("new", None)
        action.connect("activate", self.on_new_button)
        self.add_action(action)

        action = Gio.SimpleAction.new("new_terminal")  # new terminal = new tab
        action.connect("activate", self.on_new_terminal_button)
        self.add_action(action)

        action = Gio.SimpleAction.new("open_report")
        action.connect("activate", self.on_open_report_button)
        self.add_action(action)

        dirname = os.path.dirname(os.path.abspath(__file__))
        builder = Gtk.Builder.new_from_file(dirname + '/menubar.xml')
        builder.connect_signals(self)
        appmenu = builder.get_object('appmenu')
        self.set_app_menu(appmenu)
        helpMenu = builder.get_object('Help')
        self.set_menubar(helpMenu)

    def do_activate(self):
        """If there's no window, create one and present it (show it to user).
        If there's a window, just present it"""

        # We only allow a single window and raise any existing ones
        if not self.window:
            # Windows are associated with the application
            # when the last one is closed the application shuts down
            self.window = AppWindow(self.sidebar,
                                    self.terminal,
                                    self.console_log,
                                    self.statusbar,
                                    application=self,
                                    title="Faraday")

        self.window.set_icon(self.icon)
        self.window.present()

        self.loghandler = GUIHandler()
        model.guiapi.setMainApp(self)
        addHandler(self.loghandler)
        self.loghandler.registerGUIOutput(self.window)

        notifier = model.log.getNotifier()
        notifier.widget = self.window
        model.guiapi.notification_center.registerWidget(self.window)

    def postEvent(self, receiver, event):
        """Handles the events from gui/customevents."""
        if receiver is None:
            receiver = self.getMainWindow()

        elif event.type() == 3131:  # new log event
            receiver.emit("new_log", event.text)

        elif event.type() == 3141:  # new conflict event
            receiver.emit("set_conflict_label", event.nconflicts)

        elif event.type() == 5100:  # new notification event
            self.notificationsModel.prepend([event.change.getMessage()])
            receiver.emit("new_notif")
            host_count, service_count, vuln_count = self.update_counts()
            receiver.emit("update_ws_info", host_count,
                          service_count, vuln_count)

        elif event.type() == 4100 or event.type() == 3140:  # newinfo or changews
            host_count, service_count, vuln_count = self.update_counts()

            self.updateHosts()
            self.hosts_sidebar.update(self.all_hosts)

            receiver.emit("update_ws_info", host_count,
                          service_count, vuln_count)

        elif event.type() == 3132:  # error
            self.window.emit("normal_error", event.text)

        elif event.type() == 3134:  # important error, uncaught exception
            self.window.prepare_important_error(event)
            self.window.emit("important_error")

        elif event.type() == 42424: # lost connection to couch db
            self.window.prepare_important_error(event,
                                                self.handle_connection_lost)
            self.window.emit("lost_db_connection", event.problem)
            self.reloadWorkspaces()
            ws = self.openDefaultWorkspace()
            CONF.setLastWorkspace(ws.name)
            CONF.saveConfig()

    def connect_to_couch(self, couch_uri):
        """Tries to connect to a CouchDB on a specified Couch URI.
        Returns the success status of the operation, False for not successful,
        True for successful
        """
        if not CouchDbManager.testCouch(couch_uri):
            errorDialog(self.window, "The provided URL is not valid",
                        "Are you sure CouchDB is running?")
            success = False
        elif couch_uri.startswith("https://"):
            if not checkSSL(couch_uri):
                errorDialog(self.window,
                            "The SSL certificate validation has failed")
            success = False
        else:
            CONF.setCouchUri(couch_uri)
            CONF.saveConfig()
            self.reloadWorkspaces()
            success = True
        return success

    def handle_connection_lost(self, button=None, dialog=None):
        """Tries to connect to Couch using the same URI"""
        couch_uri = CONF.getCouchURI()
        if self.connect_to_couch(couch_uri):
            if dialog is not None:
                dialog.destroy()
            reconnected = True
        else:
            reconnected = False
        return reconnected

    def update_counts(self):
        """Update the counts for host, services and vulns"""
        host_count = self.model_controller.getHostsCount()
        service_count = self.model_controller.getServicesCount()
        vuln_count = self.model_controller.getVulnsCount()
        return host_count, service_count, vuln_count

    def on_open_report_button(self, action, param):
        """What happens when the user clicks the open report button.
        A dialog will present itself with a combobox to select a plugin.
        Then a file chooser to select a report. The report will be processed
        with the selected plugin.
        """

        def select_plugin():
            """Creates a simple dialog with a combo box to select a plugin"""
            plugins_id = [_id for _id in self.plugin_manager.getPlugins()]
            plugins_id = sorted(plugins_id)
            dialog = Gtk.Dialog("Select plugin", self.window, 0)

            combo_box = Gtk.ComboBoxText()
            for plugin_id in plugins_id:
                combo_box.append_text(plugin_id)
            combo_box.show()

            dialog.vbox.pack_start(combo_box, True, True, 10)

            dialog.add_button("Cancel", Gtk.ResponseType.DELETE_EVENT)
            dialog.add_button("OK", Gtk.ResponseType.ACCEPT)

            response = dialog.run()
            selected = combo_box.get_active_text()

            dialog.destroy()
            return response, selected

        def on_file_selected(plugin_id, report):
            """Send the plugin_id and the report file to be processed"""
            self.report_manager.sendReportToPluginById(plugin_id, report)

        plugin_response, plugin_id = select_plugin()

        if plugin_response == Gtk.ResponseType.ACCEPT:
            while plugin_id is None:
                # force user to select a plugin if he did not do it
                errorDialog(self.window,
                            "Please select a plugin to parse your report!")
                plugin_response, plugin_id = select_plugin()

            dialog = Gtk.FileChooserNative()
            dialog.set_title("Import a report")
            dialog.set_modal(True)
            dialog.set_transient_for(self.window)
            dialog.set_action(Gtk.FileChooserAction.OPEN)

            res = dialog.run()
            if res == Gtk.ResponseType.ACCEPT:
                on_file_selected(plugin_id, dialog.get_filename())
            dialog.destroy()

    def on_about(self, action, param):
        """ Defines what happens when you press 'about' on the menu"""

        about_dialog = aboutDialog(self.window)
        about_dialog.run()
        about_dialog.destroy()

    def on_help(self, action, param):
        """Defines what happens when user press 'help' on the menu"""

        help_dialog = helpDialog(self.window)
        help_dialog.run()
        help_dialog.destroy()

    def on_preferences(self, action, param):
        """Defines what happens when you press 'preferences' on the menu.
        Sends as a callback reloadWsManager, so if the user actually
        changes her Couch URL, the sidebar will reload reflecting the
        new workspaces available"""

        preference_window = PreferenceWindowDialog(self.reloadWorkspaces,
                                                   self.connect_to_couch,
                                                   self.window)
        preference_window.show_all()

    def show_host_info(self, host_id):
        """Looks up the host selected in the HostSidebar by id and shows
        its information on the HostInfoDialog"""

        for host in self.all_hosts:
            if host_id == host.id:
                selected_host = host
                break

        info_window = HostInfoDialog(self.window, selected_host)
        info_window.show_all()

    def reloadWorkspaces(self):
        """Used in conjunction with on_preferences: close workspace,
        resources the workspaces available, clears the sidebar of the old
        workspaces and injects all the new ones in there too"""
        self.workspace_manager.closeWorkspace()
        self.workspace_manager.resource()
        self.ws_sidebar.clearSidebar()
        self.ws_sidebar.refreshSidebar()

    def on_pluginOptions(self, action, param):
        """Defines what happens when you press "Plugins" on the menu"""
        pluginsOption_window = PluginOptionsDialog(self.plugin_manager,
                                                   self.window)
        pluginsOption_window.show_all()

    def on_new_button(self, action=None, params=None, title=None):
        "Defines what happens when you press the 'new' button on the toolbar"
        new_workspace_dialog = NewWorkspaceDialog(self.createWorkspace,
                                                  self.workspace_manager,
                                                  self.ws_sidebar, self.window,
                                                  title)
        new_workspace_dialog.show_all()

    def on_new_terminal_button(self, action, params):
        """When the user clicks on the new_terminal button, creates a new
        instance of the Terminal and tells the window to add it as a new tab
        for the notebook"""
        new_terminal = Terminal(CONF)
        the_new_terminal = new_terminal.getTerminal()
        AppWindow.new_tab(self.window, the_new_terminal)

    def on_click_notifications(self, button):
        """Defines what happens when the user clicks on the notifications
        button."""

        notifications_view = Gtk.TreeView(self.notificationsModel)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Notifications", renderer, text=0)
        notifications_view.append_column(column)
        notifications_dialog = NotificationsDialog(notifications_view,
                                                   self.delete_notifications,
                                                   self.window)
        notifications_dialog.show_all()

    def on_click_conflicts(self, button=None):
        """Doesn't use the button at all. Shows the conflict dialog"""
        self.updateConflicts()
        if self.conflicts:
            dialog = ConflictsDialog(self.conflicts,
                                     self.window)
            dialog.show_all()
            self.updateConflicts()

        else:
            dialog = Gtk.MessageDialog(self.window, 0,
                                       Gtk.MessageType.INFO,
                                       Gtk.ButtonsType.OK,
                                       "No conflicts to fix!")
            dialog.run()
            dialog.destroy()

    def delete_notifications(self):
        """Clear the notifications model of all info, also send a signal
        to get the notification label to 0 on the main window's button
        """
        self.notificationsModel.clear()
        self.window.emit("clear_notifications")

    def changeWorkspace(self, selection):
        """Changes workspace in a separate thread. Emits a signal
        to present a 'Loading workspace' dialog while Faraday processes
        the change"""

        tree_model, treeiter = selection.get_selected()
        workspaceName = tree_model[treeiter][0]

        def background_process():
            self.window.emit("loading_workspace", 'show')
            try:
                ws = super(GuiApp, self).openWorkspace(workspaceName)
                self.updateHosts()
                self.hosts_sidebar.update(self.all_hosts)
                self.window.emit("loading_workspace", "destroy")
            except Exception as e:
                self.window.emit("loading_workspace", "destroy")
                model.guiapi.notification_center.showDialog(str(e))
                ws = self.openDefaultWorkspace()

            workspace = ws.name
            CONF.setLastWorkspace(workspace)
            CONF.saveConfig()

            return True

        thread = threading.Thread(target=background_process)
        thread.daemon = True
        thread.start()

    def run(self, args):
        """First method to run, as defined by FaradayUi. This method is
        mandatory"""

        workspace = args.workspace
        try:
            ws = super(GuiApp, self).openWorkspace(workspace)
        except Exception as e:
            getLogger(self).error(
                ("Your last workspace %s is not accessible, "
                 "check configuration") % workspace)
            getLogger(self).error(str(e))
            ws = self.openDefaultWorkspace()
        workspace = ws.name

        CONF.setLastWorkspace(workspace)
        CONF.saveConfig()
        Gtk.Application.run(self)

    def on_quit(self, action, param):
        self.quit()
