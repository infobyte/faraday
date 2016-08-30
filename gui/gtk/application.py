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
import webbrowser

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
from persistence.server import models
from appwindow import AppWindow

from server import ServerIO
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
from dialogs import ImportantErrorDialog

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
        self.loading_dialog_raised = None
        self.icons = CONF.getImagePath() + "icons/"
        faraday_icon = self.icons + "faraday_icon.png"
        self.icon = GdkPixbuf.Pixbuf.new_from_file_at_scale(faraday_icon, 16,
                                                            16, False)
        self.window = None
        self.model_controller = model_controller

    @property
    def active_ws_name(self):
        return self.get_active_workspace().name

    def getMainWindow(self):
        """Useless mostly, but guiapi uses this method to access the main
        window."""
        return self.window

    def createWorkspace(self, name, description=""):
        """Uses the instance of workspace manager passed into __init__ to
        get all the workspaces names and see if they don't clash with
        the one the user wrote. If everything's fine, it saves the new
        workspace and returns True. If something went wrong, return False"""

        if name in self.workspace_manager.getWorkspacesNames():
            error_str = "A workspace with name %s already exists" % name
            model.api.log(error_str, "ERROR")
            errorDialog(self.window, error_str)
            creation_ok = False
        else:
            model.api.log("Creating workspace '%s'" % name)
            model.api.devlog("Looking for the delegation class")
            manager = self.getWorkspaceManager()
            try:
                name = manager.createWorkspace(name, description)
                self.change_workspace(name)
                creation_ok = True
            except Exception as e:
                model.guiapi.notification_center.showDialog(str(e))
                creation_ok = False

        return creation_ok

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

        if explanatory_message and isinstance(explanatory_message, basestring):
            explanation = "\n The specific error was: " + explanatory_message
        else:
            explanation = ""

        dialog = Gtk.MessageDialog(self.window, 0,
                                   Gtk.MessageType.ERROR,
                                   Gtk.ButtonsType.NONE,
                                   "The client can't connect to Faraday Server. "
                                   "You can try to reconnect to the last URL "
                                   "you set up, change it or exit Faraday "
                                   "until you fix the problem. \n"
                                   "For more information about Faraday Server "
                                   "please refer to the Faraday Github Wiki. \n "
                                   + explanation)

        dialog.set_deletable(False)

        dialog.set_modal(True)
        dialog.connect("key_press_event", do_nothing_on_key_stroke)

        retry_button = dialog.add_button("Retry connection?", 42)
        retry_button.connect("clicked", handle_connection_lost, dialog)

        change_couch_url = dialog.add_button("Change server IP?", 43)
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

        if not self.serverIO.is_server_up():
            # make sure it is not because we're not connected to Couch
            # there's another whole strategy for that.
            return False

        self.workspace_dialogs_raised = True

        available_workspaces = self.serverIO.get_workspaces_names()
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
        self.ws_sidebar.select_ws_by_name(self.active_ws_name)

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
                              "to a valid Faraday Server.")
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

        preference_window.run()

    def connect_to_couch(self, couch_uri, parent=None):
        """Tries to connect to a CouchDB on a specified Couch URI.
        Returns the success status of the operation, False for not successful,
        True for successful
        """
        if parent is None:
            parent = self.window

        if not self.serverIO.is_server_up():
            errorDialog(parent, "Could not connect to Faraday Server.",
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
        # host_count = self.model_controller.getHostsCount()
        # service_count = self.model_controller.getServicesCount()
        # vuln_count = self.model_controller.getVulnsCount()
        host_count = self.serverIO.get_hosts_number()
        service_count = self.serverIO.get_services_number()
        vuln_count = self.serverIO.get_vulns_number()
        return host_count, service_count, vuln_count

    def show_host_info(self, host_id):
        """Looks up the host selected in the HostSidebar by id and shows
        its information on the HostInfoDialog.

        Return True if everything went OK, False if there was a problem
        looking for the host."""
        current_ws_name = self.get_active_workspace().name

        #for host in self.model_controller.getAllHosts():
        for host in self.serverIO.get_hosts():
            if host_id == host.id:
                selected_host = host
                break
        else:
            self.show_normal_error("The host you clicked isn't accessible. "
                                   "This is most probably due to an internal "
                                   "error.")
            return False

        info_window = HostInfoDialog(self.window, current_ws_name, selected_host)
        info_window.show_all()
        return True

    def reload_workspaces_no_connection(self):
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
        self.ws_sidebar.clear_sidebar()
        self.ws_sidebar.refresh_sidebar()

    def delete_notifications(self):
        """Clear the notifications model of all info, also send a signal
        to get the notification label to 0 on the main window's button
        """
        self.notificationsModel.clear()
        GObject.idle_add(self.statusbar.set_default_notif_label)

    def change_workspace(self, workspace_name):
        """Changes workspace in a separate thread. Emits a signal
        to present a 'Loading workspace' dialog while Faraday processes
        the change"""

        def loading_workspace(action):
            """Function to be called via GObject.idle_add by the background
            process.  Preconditions: show must have been called before destroy
            can be called.
            """

            if action == "show" and not self.loading_dialog_raised:
                message_string = ("Loading workspace {0}. Please wait. \n"
                                  "To cancel, press Alt+F4 or a similar shorcut."
                                  .format(workspace_name))

                self.loading_dialog_raised = True
                self.loading_dialog = Gtk.MessageDialog(self.window, 0,
                                                        Gtk.MessageType.INFO,
                                                        Gtk.ButtonsType.NONE,
                                                        message_string)

                self.loading_dialog.set_modal(True)

                # on every key stroke just return true, wont allow user
                # to press scape
                self.loading_dialog.connect("key_press_event",
                                            lambda _, __: True)

                self.loading_dialog.connect("delete_event",
                                            lambda _, __: self.handle_no_active_workspace())

                self.loading_dialog.show_all()

            if action == "destroy":
                self.loading_dialog.destroy()
                self.loading_dialog_raised = False

        def background_process():
            """Change workspace. This function runs on a separated thread
            created by the parent function. DO NOT call any Gtk methods
            withing its scope, except by emiting signals to the window
            """
            GObject.idle_add(loading_workspace, 'show')
            try:
                ws = super(GuiApp, self).openWorkspace(workspace_name)
                GObject.idle_add(CONF.setLastWorkspace, ws.name)
                GObject.idle_add(CONF.saveConfig)
            except Exception as e:
                GObject.idle_add(self.handle_no_active_workspace)
                model.guiapi.notification_center.showDialog(str(e))

            GObject.idle_add(loading_workspace, 'destroy')
            return True

        self.ws_sidebar.select_ws_by_name(workspace_name)
        thread = threading.Thread(target=background_process)
        thread.daemon = True
        thread.start()

    def open_workspace_from_args(self):
        """Opens the workspace specified in the arguemnts, if possible.
        Return True if args.workspace is set, False if not."""
        if self.args.workspace:
            workspace_name = self.args.workspace
            self.change_workspace(workspace_name)
            return True
        else:
            return False

    def open_last_workspace(self):
        """Tries to open the last workspace the user had opened. Return
        None."""
        workspace_name = CONF.getLastWorkspace()
        self.change_workspace(workspace_name)

    def run(self, args):
        """First method to run, as defined by FaradayUi. This method is
        mandatory"""
        self.args = args
        Gtk.Application.run(self)

    ##########################################################################
    # NOTE: uninteresting part below. do not touch unless you have a very    #
    # good reason, or you want to connect a new button on the toolbar,       #
    # or, maybe most probably, you wanna register a new signal on            #
    # postEvent().                                                           #
    # Remember! -- even the best advice must sometimes not be heeded.        #
    ##########################################################################

    def postEvent(self, _, event):
        """Handles the events from gui/customevents. The second
        argument is the 'receiver', but as this was made for QT3 it is now
        deprecated and we must manually set the receiver until the
        events module is updated.

        DO NOT, AND I REPEAT, DO NOT REDRAW *ANYTHING* FROM THE GUI
        FROM HERE. If you must do it, you should to it sing Glib.idle_add,
        a misterious function with outdated documentation. Good luck."""

        def new_log_event():
            GObject.idle_add(self.console_log.customEvent, event.text)

        def new_conflict_event():
            GObject.idle_add(self.statusbar.update_conflict_button_label,
                             event.nconflicts)

        def new_notification_event():
            self.notificationsModel.prepend([event.change.getMessage()])
            GObject.idle_add(self.statusbar.inc_notif_button_label)
            host_count, service_count, vuln_count = self.update_counts()
            GObject.idle_add(self.statusbar.update_ws_info, host_count,
                             service_count, vuln_count)

        def host_added_event():
            pass

        def host_deleted_event():
            GObject.idle_add(self.hosts_sidebar.update, 'delete', event.host_id)
            host_count, service_count, vuln_count = self.update_counts()
            GObject.idle_add(self.statusbar.update_ws_info, host_count,
                             service_count, vuln_count)

        def host_updated_event():
            GObject.idle_add(self.hosts_sidebar.update, 'update', event.host)
            host_count, service_count, vuln_count = self.update_counts()
            GObject.idle_add(self.statusbar.update_ws_info, host_count,
                             service_count, vuln_count)

        def workspace_changed_event():
            self.serverIO.active_workspace = event.workspace.name
            host_count, service_count, vuln_count = self.update_counts()
            total_host_amount = self.serverIO.get_hosts_number()
            first_host_page = self.serverIO.get_hosts(page='0', page_size='20', sort='vulns', sort_dir='desc')
            GObject.idle_add(self.hosts_sidebar.redo, first_host_page, total_host_amount)
            GObject.idle_add(self.statusbar.update_ws_info, host_count,
                             service_count, vuln_count)
            GObject.idle_add(self.select_active_workspace)

        def normal_error_event():
            GObject.idle_add(self.show_normal_error, event.text)

        def important_error_event():
            GObject.idle_add(self.show_important_error, event)

        def lost_connection_to_server_event():
            GObject.idle_add(self.lost_db_connection, event.problem,
                             self.handle_connection_lost,
                             self.force_change_couch_url)
            GObject.idle_add(self.reload_workspaces_no_connection)

        def workspace_not_accessible_event():
            GObject.idle_add(self.handle_no_active_workspace)

        def add_object():
            GObject.idle_add(self.hosts_sidebar.add_object, event.new_obj)
            host_count, service_count, vuln_count = self.update_counts()
            GObject.idle_add(self.statusbar.update_ws_info, host_count,
                             service_count, vuln_count)

        def delete_object():
            pass

        def edit_object():
            pass

        dispatch = {3131:  new_log_event,
                    3141:  new_conflict_event,
                    5100:  new_notification_event,
                    4100:  host_added_event,
                    4101:  host_deleted_event,
                    4102:  host_updated_event,
                    3140:  workspace_changed_event,
                    3132:  normal_error_event,
                    3134:  important_error_event,
                    42424: lost_connection_to_server_event,
                    24242: workspace_not_accessible_event,
                    7777:  add_object,
                    8888:  delete_object,
                    9999:  edit_object}

        function = dispatch.get(event.type())
        if function is not None:
            function()

    def show_normal_error(self, dialog_text):
        """Just a simple, normal, ignorable error"""
        dialog = Gtk.MessageDialog(self.window, 0,
                                   Gtk.MessageType.ERROR,
                                   Gtk.ButtonsType.OK,
                                   dialog_text)
        dialog.run()
        dialog.destroy()

    def show_important_error(self, event):
        """Creates an importan error dialog with a callback to send
        the developers the error traceback.
        """
        dialog_text = event.text
        dialog = ImportantErrorDialog(self.window, dialog_text)
        response = dialog.run()
        if response == 42:
            error = event.error_name
            event.callback(error, *event.exception_objects)
        dialog.destroy()

    def do_startup(self):
        """
        GTK calls this method after Gtk.Application.run()
        Creates instances of the sidebar, terminal, console log and
        statusbar to be added to the app window.
        Sets up necesary actions on menu and toolbar buttons
        Also reads the .xml file from menubar.xml
        """
        Gtk.Application.do_startup(self)  # deep GTK magic

        self.serverIO = ServerIO(CONF.getLastWorkspace())
        self.ws_sidebar = WorkspaceSidebar(self.serverIO,
                                           self.change_workspace,
                                           self.remove_workspace,
                                           self.on_new_button,
                                           CONF.getLastWorkspace())

        workspace_argument_set = self.open_workspace_from_args()
        if not workspace_argument_set:
            self.open_last_workspace()

        # the dummy values here will be updated as soon as the ws is loaded.
        self.hosts_sidebar = HostsSidebar(self.show_host_info, self.serverIO.get_hosts,
                                          self.icons)
        default_model = self.hosts_sidebar.create_model([]) # dummy empty list
        self.hosts_sidebar.create_view(default_model)
        self.sidebar = Sidebar(self.ws_sidebar.get_box(),
                               self.hosts_sidebar.get_box())

        host_count, service_count, vuln_count = 0, 0, 0  # dummy values
        self.terminal = Terminal(CONF)
        self.console_log = ConsoleLog()
        self.statusbar = Statusbar(self.on_click_notifications,
                                   self.on_click_conflicts,
                                   host_count, service_count, vuln_count)

        self.notificationsModel = Gtk.ListStore(str)

        action_to_method = {"about": self.on_about,
                            "help": self.on_help,
                            "quit": self.on_quit,
                            "preferences": self.on_preferences,
                            "pluginOptions": self.on_plugin_options,
                            "new": self.on_new_button,
                            "new_terminal": self.on_new_terminal_button,
                            "open_report": self.on_open_report_button,
                            "go_to_web_ui": self.on_click_go_to_web_ui_button
                            }

        for action, method in action_to_method.items():
            gio_action = Gio.SimpleAction.new(action, None)
            gio_action.connect("activate", method)
            self.add_action(gio_action)

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
                                    title="Faraday " + str(CONF.getVersion()))

        self.window.set_icon(self.icon)
        self.window.present()

        self.loghandler = GUIHandler()
        model.guiapi.setMainApp(self)
        addHandler(self.loghandler)
        self.loghandler.registerGUIOutput(self.window)

        notifier = model.log.getNotifier()
        notifier.widget = self.window
        model.guiapi.notification_center.registerWidget(self.window)

        if not self.serverIO.is_server_up():
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
        terminal_scrolled = new_terminal.create_scrollable_terminal()
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
        conflicts = self.model_controller.getConflicts()
        if conflicts:
            dialog = ConflictsDialog(conflicts,
                                     self.window)
            dialog.show_all()

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

    def on_click_go_to_web_ui_button(self, action=None, param=None):
        """Opens the dashboard of the current workspace on a new tab of
        the user's default browser
        """
        couch_url = CONF.getCouchURI()
        ws_name = self.workspace_manager.getActiveWorkspace().name
        ws_url = couch_url + "/_ui/#/dashboard/ws/" + ws_name
        webbrowser.open(ws_url, new=2)
