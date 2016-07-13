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
           "version 3.14 or above (recommended) or 3.12")
    sys.exit(1)

try:
    gi.require_version('Gtk', '3.0')
except ValueError:
    print ("WARNING: You don't seem to have installed the recommended version"
           " of GTK. You can still use the program, but we recommend you"
           " check your install of GTK+3")

try:
    gi.require_version('Vte', '2.91')
except ValueError:
    gi.require_version('Vte', '2.90')

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
from dialogs import ForceChooseWorkspaceDialog
from dialogs import ForceNewWorkspaceDialog
from dialogs import ForcePreferenceWindowDialog
from dialogs import errorDialog

from mainwidgets import Sidebar
from mainwidgets import WorkspaceSidebar
from mainwidgets import HostsSidebar
from mainwidgets import ConsoleLog
from mainwidgets import Terminal
from mainwidgets import Statusbar

from gui.loghandler import GUIHandler
from utils.logs import addHandler
from utils.common import checkSSL

CONF = getInstanceConfiguration()


class GuiApp(Gtk.Application, FaradayUi):
    """
    Creates the application and has the necesary callbacks to FaradayUi
    As far as the GUI goes, this handles only the menu, everything is else is
    appWindow's resposibility. All logic by the main window should be done
    here. Some of the logic on the dialogs is implemented in the dialogs own
    class. Some dialogs are shown by the appwindow to handle errors coming
    from other threads outside GTK's.

    Please respect the following structure:
    TOP: __init__
    UPPER-MIDDLE: all logic mostly not inherited fom Gtk.Application
    LOWER-MIDDLE: all do_ starting, gtk related methods
    BOTTOM: all on_ starting, dialog opener methods

    """

    def __init__(self, model_controller, plugin_manager, workspace_manager,
                 plugin_controller):
        """Does not do much. Most of the initialization work is actually
        done by the run() method, as specified in FaradayUi."""

        FaradayUi.__init__(self,
                           model_controller,
                           plugin_manager,
                           workspace_manager,
                           plugin_controller)

        Gtk.Application.__init__(self, application_id="org.infobyte.faraday",
                                 flags=Gio.ApplicationFlags.FLAGS_NONE)

        self.lost_connection_dialog_raised = None
        self.workspace_dialogs_raised = None
        self.icons = CONF.getImagePath() + "icons/"
        faraday_icon = self.icons + "faraday_icon.png"
        self.icon = GdkPixbuf.Pixbuf.new_from_file_at_scale(faraday_icon, 16,
                                                            16, False)
        self.window = None
        self.model_controller = model_controller
        self.conflicts = self.model_controller.getConflicts()

    def getMainWindow(self):
        """Useless mostly, but guiapi uses this method to access the main
        window."""
        return self.window

    def updateConflicts(self):
        """Reassings self.conflicts with an updated list of conflicts"""
        self.conflicts = self.model_controller.getConflicts()

    def updateHosts(self):
        """Reassings the value of self.all_hosts to a current one to
        catch workspace changes, new hosts added via plugins or any other
        external interference with our host list"""
        self.all_hosts = self.model_controller.getAllHosts()
        return self.all_hosts

    def createWorkspace(self, name, description=""):
        """Uses the instance of workspace manager passed into __init__ to
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
                                            manager.namedTypeToDbType('CouchDB'))
                CONF.setLastWorkspace(w.name)
                CONF.saveConfig()
                status = True
            except Exception as e:
                status = False
                model.guiapi.notification_center.showDialog(str(e))

        return status

    def remove_workspace(self, button, ws_name):
        """Removes a workspace. If the workspace to be deleted is the one
        selected, it moves you first to the default. The clears and refreshes
        sidebar"""

        model.api.log("Removing Workspace: %s" % ws_name)
        self.getWorkspaceManager().removeWorkspace(ws_name)
        self.ws_sidebar.clear_sidebar()
        self.ws_sidebar.refresh_sidebar()
        self.select_active_workspace()

    def lost_db_connection(self, explanatory_message=None,
                           handle_connection_lost=None,
                           connect_to_a_different_couch=None):
        """Creates a simple dialog with an error message to inform the user
        some kind of problem has happened and the connection was lost.
        """

        # NOTE: if we start faraday without CouchDB, both the signal coming
        # from CouchDB manager AND our test in do_activate will try
        # to raise the dialog. This avoids more than one dialog to be raised.
        if self.lost_connection_dialog_raised:
            return False

        def do_nothing_on_key_stroke(event, key):
            """Do nothing except return True"""
            return True

        self.lost_connection_dialog_raised = True

        if explanatory_message:
            explanation = "\n The specific error was: " + explanatory_message
        else:
            explanation = ""

        dialog = Gtk.MessageDialog(self.window, 0,
                                   Gtk.MessageType.ERROR,
                                   Gtk.ButtonsType.NONE,
                                   "Faraday can't connect to CouchDB. "
                                   "You can try to reconnect to the last URL "
                                   "you set up, change it or exit Faraday "
                                   "until you fix the problem. \n" + explanation)

        dialog.set_deletable(False)
        dialog.set_modal(True)
        dialog.connect("key_press_event", do_nothing_on_key_stroke)

        retry_button = dialog.add_button("Retry connection?", 42)
        retry_button.connect("clicked", handle_connection_lost, dialog)

        change_couch_url = dialog.add_button("Connect to a different CouchDB?", 43)
        change_couch_url.connect("clicked", connect_to_a_different_couch, dialog)

        cancel_button = dialog.add_button("Exit Faraday", 0)
        cancel_button.connect("clicked", self.on_quit)

        response = dialog.run()
        if response == Gtk.ResponseType.DELETE_EVENT:
            GObject.idle_add(self.exit_faraday_without_confirm)

    def handle_no_active_workspace(self):
        """If there's been a problem opening a workspace or for some reason
        we suddenly find our selves without one, force the user
        to select one if possible, or if not, to create one.
        """
        def change_flag(widget):
            self.workspace_dialogs_raised = not self.workspace_dialogs_raised

        if self.workspace_dialogs_raised:
            return False

        if not CouchDbManager.testCouch(CONF.getCouchURI()):
            # make sure it is not because we're not connected to Couch
            # there's another whole strategy for that.
            return False

        self.workspace_dialogs_raised = True

        available_workspaces = self.workspace_manager.getWorkspacesNames()
        workspace_model = self.ws_sidebar.workspace_model

        if available_workspaces:
            dialog = ForceChooseWorkspaceDialog(self.window,
                                                workspace_model,
                                                self.change_workspace)

        else:
            dialog = ForceNewWorkspaceDialog(self.window,
                                             self.createWorkspace,
                                             self.workspace_manager,
                                             self.ws_sidebar,
                                             self.exit_faraday)

        dialog.connect("destroy", change_flag)
        dialog.show_all()

    def select_active_workspace(self):
        """Selects on the sidebar the currently active workspace."""
        active_ws_name = self.get_active_workspace().name
        self.ws_sidebar.select_ws_by_name(active_ws_name)

    def get_active_workspace(self):
        """Return the currently active workspace"""
        return self.workspace_manager.getActiveWorkspace()

    def exit_faraday(self, button=None, parent=None):
        """A simple exit which will ask for confirmation."""
        if not self.window.do_delete_event(parent):
            if parent is not None:
                GObject.idle_add(parent.destroy)
            GObject.idle_add(self.window.destroy)

    def exit_faraday_without_confirm(self, widget=None):
        """Exits faraday without confirm. Used as a middle-man between
        connect callbacks (which will send the widget as an argument and
        self.window.destroy, which takes none.
        """
        getLogger(self).error("Faraday exited because you didn't connect "
                              "to a valid CouchDB.")
        GObject.idle_add(self.window.destroy)
        GObject.idle_add(self.on_quit)

    def force_change_couch_url(self, button=None, dialog=None):
        """Forces the user to change the couch URL. You **will** ended up
        connected to CouchDB or you will exit my application, cowboy.
        """

        # destroy the ugly dialog that got us here
        if dialog is not None:
            dialog.destroy()

        preference_window = ForcePreferenceWindowDialog(self.reload_workspaces,
                                                        self.connect_to_couch,
                                                        self.window,
                                                        self.exit_faraday)

        preference_window.connect("destroy", self.exit_faraday_without_confirm)
        preference_window.run()

    def connect_to_couch(self, couch_uri, parent=None):
        """Tries to connect to a CouchDB on a specified Couch URI.
        Returns the success status of the operation, False for not successful,
        True for successful
        """
        if parent is None:
            parent = self.window

        if not CouchDbManager.testCouch(couch_uri):
            errorDialog(parent, "Could not connect to CouchDB.",
                        ("Are you sure it is running and that you can "
                         "connect to it? \n Make sure your username and "
                         "password are still valid."))
            success = False
        elif couch_uri.startswith("https://"):
            if not checkSSL(couch_uri):
                errorDialog(self.window,
                            "The SSL certificate validation has failed")
            success = False
        else:
            CONF.setCouchUri(couch_uri)
            CONF.saveConfig()
            self.reload_workspaces()
            self.open_last_workspace()
            success = True
            self.lost_connection_dialog_raised = False
        return success

    def handle_connection_lost(self, button=None, dialog=None):
        """Tries to connect to Couch using the same URI"""
        couch_uri = CONF.getCouchURI()
        if self.connect_to_couch(couch_uri, parent=dialog):
            reconnected = True
            if dialog is not None:
                dialog.destroy()
                self.open_last_workspace()
                self.lost_connection_dialog_raised = False
        else:
            reconnected = False
        return reconnected

    def update_counts(self):
        """Update the counts for host, services and vulns"""
        host_count = self.model_controller.getHostsCount()
        service_count = self.model_controller.getServicesCount()
        vuln_count = self.model_controller.getVulnsCount()
        return host_count, service_count, vuln_count

    def show_host_info(self, host_id):
        """Looks up the host selected in the HostSidebar by id and shows
        its information on the HostInfoDialog"""
        current_ws_name = self.get_active_workspace().name

        for host in self.all_hosts:
            if host_id == host.id:
                selected_host = host
                break

        info_window = HostInfoDialog(self.window, current_ws_name, selected_host)
        info_window.show_all()

    def reload_worskpaces_no_connection(self):
        """Very similar to reload_workspaces, but doesn't resource the
        workspace_manager to avoid asking for information to a database
        we can't access."""
        self.workspace_manager.closeWorkspace()
        self.ws_sidebar.clear_sidebar()

    def reload_workspaces(self):
        """Close workspace, resources the workspaces available,
        clears the sidebar of the old workspaces and injects all the new ones
        in there too"""
        self.workspace_manager.closeWorkspace()
        self.workspace_manager.resource()
        self.ws_sidebar.clear_sidebar()
        self.ws_sidebar.refresh_sidebar()

    def delete_notifications(self):
        """Clear the notifications model of all info, also send a signal
        to get the notification label to 0 on the main window's button
        """
        self.notificationsModel.clear()
        self.window.emit("clear_notifications")

    def change_workspace(self, workspace_name):
        """Changes workspace in a separate thread. Emits a signal
        to present a 'Loading workspace' dialog while Faraday processes
        the change"""
        self.ws_sidebar.select_ws_by_name(workspace_name)

        def background_process():
            """Change workspace. This function runs on a separated thread
            created by the parent function. DO NOT call any Gtk methods
            withing its scope, except by emiting signals to the window
            """
            self.window.emit("loading_workspace", 'show')
            try:
                ws = super(GuiApp, self).openWorkspace(workspace_name)
                self.window.emit("loading_workspace", "destroy")
                GObject.idle_add(CONF.setLastWorkspace, ws.name)
                GObject.idle_add(CONF.saveConfig)
            except Exception as e:
                self.handle_no_active_workspace()
                model.guiapi.notification_center.showDialog(str(e))
                self.window.emit("loading_workspace", "destroy")

            return True

        thread = threading.Thread(target=background_process)
        thread.daemon = True
        thread.start()

    def open_last_workspace(self):
        """Tries to open the last workspace the user had opened."""
        workspace = self.args.workspace
        try:
            ws = super(GuiApp, self).openWorkspace(workspace)
            workspace = ws.name
            CONF.setLastWorkspace(workspace)
            CONF.saveConfig()
        except Exception as e:
            self.handle_no_active_workspace()
            getLogger(self).error(
                ("Your last workspace %s is not accessible, "
                 "check configuration") % workspace)
            getLogger(self).error(str(e))

    def run(self, args):
        """First method to run, as defined by FaradayUi. This method is
        mandatory"""
        self.args = args
        Gtk.Application.run(self)

    ##########################################################################
    # NOTE: uninteresting part below. do not touch unless you have a very    #
    # good reason, or you wan't to connect a new button on the toolbar,      #
    # or, maybe most probably, you wanna register a new signal on            #
    # postEvent().                                                           #
    # Remember! -- even the best advice must sometimes not be heeded.        #
    ##########################################################################

    def postEvent(self, receiver, event):
        """Handles the events from gui/customevents.

        DO NOT, AND I REPEAT, DO NOT REDRAW *ANYTHING* FROM THE GUI
        FROM HERE. If you must do it, you should to it via the emit method
        to the appwindow or maybe using Glib.idle_add, a misterious function
        with outdated documentation. Good luck."""

        if receiver is None:
            receiver = self.window

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
            self.window.receive_hosts(self.updateHosts())
            receiver.emit("update_hosts_sidebar")
            receiver.emit("update_ws_info", host_count, service_count, vuln_count)
            GObject.idle_add(self.select_active_workspace)

        elif event.type() == 3132:  # error
            self.window.emit("normal_error", event.text)

        elif event.type() == 3134:  # important error, uncaught exception
            GObject.idle_add(self.window.prepare_important_error, event)
            self.window.emit("important_error")

        elif event.type() == 42424:  # lost connection to couch db
            GObject.idle_add(self.lost_db_connection, event.problem,
                             self.handle_connection_lost,
                             self.force_change_couch_url)
            GObject.idle_add(self.reload_worskpaces_no_connection)

        elif event.type() == 24242:  # workspace not accesible
            GObject.idle_add(self.handle_no_active_workspace)

    def do_startup(self):
        """
        GTK calls this method after Gtk.Application.run()
        Creates instances of the sidebar, terminal, console log and
        statusbar to be added to the app window.
        Sets up necesary actions on menu and toolbar buttons
        Also reads the .xml file from menubar.xml
        """
        Gtk.Application.do_startup(self)  # deep GTK magic

        self.open_last_workspace()
        self.ws_sidebar = WorkspaceSidebar(self.workspace_manager,
                                           self.change_workspace,
                                           self.remove_workspace,
                                           self.on_new_button,
                                           CONF.getLastWorkspace())

        self.updateHosts()
        self.hosts_sidebar = HostsSidebar(self.show_host_info, self.icons)
        default_model = self.hosts_sidebar.create_model(self.all_hosts)
        self.hosts_sidebar.create_view(default_model)

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
        action.connect("activate", self.on_plugin_options)
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
        If there's a window, just present it. Also add the log handler
        and the notifier to the application"""

        # We only allow a single window and raise any existing ones
        if not self.window:
            # Windows are associated with the application
            # when the last one is closed the application shuts down
            self.window = AppWindow(self.sidebar,
                                    self.ws_sidebar,
                                    self.hosts_sidebar,
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

        if not CouchDbManager.testCouch(CONF.getCouchURI()):
            self.lost_db_connection(
                handle_connection_lost=self.handle_connection_lost,
                connect_to_a_different_couch=self.force_change_couch_url)

    def on_quit(self, action=None, param=None):
        self.quit()

    def on_plugin_options(self, action, param):
        """Defines what happens when you press "Plugins" on the menu"""
        pluginsOption_window = PluginOptionsDialog(self.plugin_manager,
                                                   self.window)
        pluginsOption_window.show_all()

    def on_new_button(self, action=None, params=None, title=None):
        """Defines what happens when you press the 'new' button on the toolbar
        """
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
        terminal_scrolled = new_terminal.getTerminal()
        self.window.new_tab(terminal_scrolled)

    def on_click_notifications(self, button):
        """Defines what happens when the user clicks on the notifications
        button: just show a silly window with a treeview containing
        all the notifications"""

        notifications_view = Gtk.TreeView(self.notificationsModel)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Notifications", renderer, text=0)
        notifications_view.append_column(column)
        notifications_dialog = NotificationsDialog(notifications_view,
                                                   self.delete_notifications,
                                                   self.window)
        notifications_dialog.show_all()

    def on_click_conflicts(self, button=None):
        """Doesn't use the button at all, there cause GTK likes it.
        Shows the conflict dialog.
        """
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
            combo_box.set_wrap_width(3)
            for plugin_id in plugins_id:
                combo_box.append_text(plugin_id)
            combo_box.show()

            dialog.vbox.pack_start(combo_box, False, True, 10)

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

        while plugin_response == Gtk.ResponseType.ACCEPT and plugin_id is None:
            # force user to select a plugin if he did not do it
            errorDialog(self.window,
                        "Please select a plugin to parse your report!")
            plugin_response, plugin_id = select_plugin()
        else:
            if plugin_response == Gtk.ResponseType.ACCEPT:
                dialog = Gtk.FileChooserDialog(title="Import a report",
                                               parent=self.window,
                                               action=Gtk.FileChooserAction.OPEN,
                                               buttons=("Open", Gtk.ResponseType.ACCEPT,
                                                        "Cancel", Gtk.ResponseType.CANCEL)
                                               )
                dialog.set_modal(True)

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

    def on_preferences(self, action=None, param=None):
        """Defines what happens when you press 'preferences' on the menu.
        Sends as a callback reloadWsManager, so if the user actually
        changes her Couch URL, the sidebar will reload reflecting the
        new workspaces available"""

        preference_window = PreferenceWindowDialog(self.reload_workspaces,
                                                   self.connect_to_couch,
                                                   self.window)
        preference_window.show_all()
