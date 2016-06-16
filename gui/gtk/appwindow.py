#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import gi

from config.configuration import getInstanceConfiguration

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import GLib, Gio, Gtk, GObject, Gdk
from dialogs import ImportantErrorDialog
from dialogs import errorDialog

CONF = getInstanceConfiguration()


class _IdleObject(GObject.GObject):
    """
    Override GObject.GObject to always emit signals in the main thread
    by emmitting on an idle handler. Deep magic, do not touch unless
    you know what you are doing.
    """
    def __init__(self):
        GObject.GObject.__init__(self)

    def emit(self, *args):
        GObject.idle_add(GObject.GObject.emit, self, *args)


class AppWindow(Gtk.ApplicationWindow, _IdleObject):
    """The main window of the GUI. Draws the toolbar.
    Positions the terminal, sidebar, consolelog and statusbar received from
    the app and defined in the mainwidgets module"""

    __gsignals__ = {
        "new_log": (GObject.SIGNAL_RUN_FIRST, None, (str, )),
        "new_notif": (GObject.SIGNAL_RUN_FIRST, None, ()),
        "clear_notifications": (GObject.SIGNAL_RUN_FIRST, None, ()),
        "update_ws_info": (GObject.SIGNAL_RUN_FIRST, None, (int, int, int, )),
        "set_conflict_label": (GObject.SIGNAL_RUN_FIRST, None, (int, )),
        "loading_workspace": (GObject.SIGNAL_RUN_FIRST, None, (str, )),
        "update_hosts_sidebar": (GObject.SIGNAL_RUN_FIRST, None, ()),
        "normal_error": (GObject.SIGNAL_RUN_FIRST, None, (str, )),
        "important_error": (GObject.SIGNAL_RUN_FIRST, None, ()),
    }

    def __init__(self, sidebar, ws_sidebar, hosts_sidebar, terminal,
                 console_log, statusbar, *args, **kwargs):
        super(Gtk.ApplicationWindow, self).__init__(*args, **kwargs)

        # This will be in the windows group and have the "win" prefix
        glib_variant = GLib.Variant.new_boolean(True)
        max_action = Gio.SimpleAction.new_stateful("maximize", None,
                                                   glib_variant)
        max_action.connect("change-state", self.on_maximize_toggle)
        self.add_action(max_action)
        self.maximize()

        self.sidebar = sidebar
        self.ws_sidebar = ws_sidebar
        self.hosts_sidebar = hosts_sidebar
        self.terminal = terminal
        self.log = console_log
        self.statusbar = statusbar

        self.terminal.connect("child_exited", self.on_terminal_exit)

        self.icons = CONF.getImagePath() + "icons/"

        # Keep it in sync with the actual state. Deep dark GTK magic
        self.connect("notify::is-maximized",
                     lambda obj, pspec:
                     max_action.set_state(
                         GLib.Variant.new_boolean(obj.props.is_maximized)))

        # TOP BOX: TOOLBAR AND FILTER
        self.topBox = Gtk.Box()
        self.topBox.pack_start(self.create_toolbar(), True, True, 0)

        # SIDEBAR BOX
        self.sidebarBox = self.sidebar.get_box()

        # TERMINAL BOX
        self.firstTerminalBox = self.terminalBox(self.terminal.getTerminal())

        # MIDDLE PANE: NOTEBOOK AND SIDEBAR
        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self.notebook.append_page(self.firstTerminalBox, Gtk.Label("1"))

        self.middlePane = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        self.middlePane.pack1(self.notebook, True, False)
        self.middlePane.pack2(self.sidebarBox, False, False)

        # LOGGER BOX: THE LOGGER, DUH
        self.loggerBox = Gtk.Box()
        self.loggerBox.pack_start(self.log.getLogger(), True, True, 0)

        # NOTIFACTION BOX: THE BUTTON TO ACCESS NOTIFICATION DIALOG
        self.notificationBox = Gtk.Box()
        self.notificationBox.pack_start(self.statusbar.mainBox, True, True, 0)

        # MAINBOX: THE BIGGER BOX FOR ALL THE LITTLE BOXES
        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.mainBox.pack_start(self.topBox, False, False, 0)
        self.mainBox.pack_start(self.middlePane, True, True, 0)
        self.mainBox.pack_start(self.loggerBox, False, False, 0)
        self.mainBox.pack_end(self.notificationBox, False, False, 0)

        remove_terminal_icon = Gtk.Image.new_from_file(self.icons + "exit.png")
        remove_terminal_button = Gtk.Button()
        remove_terminal_button.set_tooltip_text("Delete current tab")
        remove_terminal_button.connect("clicked", self.delete_tab)
        remove_terminal_button.set_image(remove_terminal_icon)
        remove_terminal_button.set_relief(Gtk.ReliefStyle.NONE)
        remove_terminal_button.show()

        at_end = Gtk.PackType.END
        self.notebook.set_action_widget(remove_terminal_button, at_end)

        self.add(self.mainBox)
        self.tab_number = 0  # 0 indexed, even when it shows 1 to the user

        self.show_all()

    def receive_hosts(self, hosts):
        """Attaches the hosts to an object value, so it can be used by
        do_update_hosts_sidebar, a signal. GTK won't alow anything
        more than primitive names to be passed on by signals"""
        self.current_hosts = hosts

    def do_update_hosts_sidebar(self):
        self.hosts_sidebar.update(self.current_hosts)

    def terminalBox(self, terminal):
        """Given a terminal, creates an EventBox for the Box that has as a
        children said terminal"""
        eventTerminalBox = Gtk.EventBox()
        terminalBox = Gtk.Box()
        terminalBox.pack_start(terminal, True, True, 0)
        eventTerminalBox.connect("button_press_event", self.right_click)
        eventTerminalBox.add(terminalBox)
        return eventTerminalBox

    def right_click(self, eventbox, event):
        """Defines the menu created when a user rightclicks on the
        terminal eventbox"""
        menu = Gtk.Menu()
        self.copy = Gtk.MenuItem("Copy")
        self.paste = Gtk.MenuItem("Paste")
        menu.append(self.paste)
        menu.append(self.copy)

        self.copy.connect("activate", self.copy_text)
        self.paste.connect("activate", self.paste_text)

        self.copy.show()
        self.paste.show()
        menu.popup(None, None, None, None, event.button, event.time)

    def copy_text(self, _):
        """When the user presses on the copy button on the menu..."""
        currentTerminal = self.getCurrentFocusedTerminal()
        currentTerminal.copy_clipboard()

    def paste_text(self, _):
        """When the user presses on the paste button on the menu..."""
        currentTerminal = self.getCurrentFocusedTerminal()
        currentTerminal.paste_clipboard()

    def getFocusedTab(self):
        """Return the focused tab"""
        return self.notebook.get_current_page()

    def getCurrentFocusedTerminal(self):
        """Returns the current focused terminal"""

        # the focused terminal is the child of the event box which is
        # the top widget of the focused tab. that event box has as only child
        # a box, which has as only child a scrolled window, which has as
        # only child the terminal. yeah. I know.

        currentTab = self.getFocusedTab()
        currentEventBox = self.notebook.get_children()[currentTab]
        currentBox = currentEventBox.get_children()[0]
        currentScrolledWindow = currentBox.get_children()[0]
        currentTerminal = currentScrolledWindow.get_child()
        return currentTerminal

    def prepare_important_error(self, event):
        """Attaches an event to the class, so it can be used by the signal
        callbacks even if they cannot be passed directly.
        """
        self.event = event

    def do_important_error(self):
        """Creates an importan error dialog with a callback to send
        the developers the error traceback.
        """
        dialog_text = self.event.text
        dialog = ImportantErrorDialog(self, dialog_text)
        response = dialog.run()
        if response == 42:
            error = self.event.error_name
            self.event.callback(error, *self.event.exception_objects)
        dialog.destroy()

    def do_normal_error(self, dialog_text):
        """Just a simple, normal, ignorable error"""
        dialog = Gtk.MessageDialog(self, 0,
                                   Gtk.MessageType.ERROR,
                                   Gtk.ButtonsType.OK,
                                   dialog_text)
        dialog.run()
        dialog.destroy()

    def do_new_log(self, text):
        """To be used on a new_log signal. Calls a method on log to append
        to it"""
        self.log.customEvent(text)

    def do_clear_notifications(self):
        "On clear_notifications signal, it will return the button label to 0"
        self.statusbar.set_default_notif_label()

    def do_new_notif(self):
        """On a new notification, increment the button label by one"""
        self.statusbar.inc_notif_button_label()

    def do_set_conflict_label(self, conflict_number):
        """Sets the conflict label to the appropiate conflict_number"""
        self.statusbar.update_conflict_button_label(conflict_number)

    def do_update_ws_info(self, host_count, service_count, vuln_count):
        """Sets the statusbar workspace info to the appropiate numbers"""
        self.statusbar.update_ws_info(host_count, service_count, vuln_count)

    def do_loading_workspace(self, action):
        """Called by changeWorkspace on the application. Presents
        a silly loading dialog.
        Preconditions: show must have been called before destroy can be called
        """
        def do_nothing(widget, event):
            """Do nothing. Well, technically, return True.

            Avoids the user to interact with the dialog in anyway, for example,
            via the Escape key.
            You'll have to wait for my dialog to exit by itself, cowboy.
            """
            return True

        if action == "show":
            self.loading_dialog = Gtk.MessageDialog(self, 0,
                                                    Gtk.MessageType.INFO,
                                                    Gtk.ButtonsType.NONE,
                                                    ("Loading workspace. \n"
                                                    "Please wait."))

            self.loading_dialog.set_modal(True)
            self.loading_dialog.connect("key_press_event", do_nothing)

            self.loading_dialog.show_all()
        if action == "destroy":
            self.loading_dialog.destroy()


    def getLogConsole(self):
        """Returns the LogConsole. Needed by the GUIHandler logger"""
        return self.log

    def on_maximize_toggle(self, action, value):
        """Defines what happens when the window gets the signal to maximize"""
        action.set_state(value)
        if value.get_boolean():
            self.maximize()
        else:
            self.unmaximize()

    def refreshSidebar(self):
        """Call the refresh method on sidebar. It will append new workspaces,
        but it will *NOT* delete workspaces not found in the current
        ws"""
        self.sidebar.refresh()

    def create_toolbar(self):
        """ Creates toolbar with an open and new button, getting the icons
        from the stock. """

        toolbar = Gtk.Toolbar()
        toolbar.set_hexpand(True)
        toolbar.get_style_context().add_class(Gtk.STYLE_CLASS_PRIMARY_TOOLBAR)
        icons = self.icons

        # new_from_stock is deprecated, but should work fine for now
        new_button_icon = Gtk.Image.new_from_file(icons + "Documentation.png")
        new_terminal_icon = Gtk.Image.new_from_file(icons + "newshell.png")
        preferences_icon = Gtk.Image.new_from_file(icons + "config.png")
        toggle_log_icon = Gtk.Image.new_from_file(icons + "debug.png")
        open_report_icon = Gtk.Image.new_from_file(icons + "FolderSteel-20.png")

        new_terminal_button = Gtk.ToolButton.new(new_terminal_icon, None)
        new_terminal_button.set_tooltip_text("Create a new tab")
        new_terminal_button.set_action_name('app.new_terminal')
        toolbar.insert(new_terminal_button, 0)

        new_button = Gtk.ToolButton.new(new_button_icon, None)
        new_button.set_tooltip_text("Create a new workspace")
        toolbar.insert(new_button, 1)
        new_button.set_action_name('app.new')

        preferences_button = Gtk.ToolButton.new(preferences_icon, None)
        preferences_button.set_tooltip_text("Preferences")
        toolbar.insert(preferences_button, 2)
        preferences_button.set_action_name('app.preferences')

        toggle_log_button = Gtk.ToggleToolButton.new()
        toggle_log_button.set_icon_widget(toggle_log_icon)
        toggle_log_button.set_active(True)  # log enabled by default
        toggle_log_button.set_tooltip_text("Toggle log console")
        toggle_log_button.connect("clicked", self.toggle_log)
        toolbar.insert(toggle_log_button, 3)

        space = Gtk.ToolItem()
        space.set_expand(True)
        toolbar.insert(space, 4)

        open_report_button = Gtk.ToolButton.new(open_report_icon, None)
        open_report_button.set_tooltip_text("Import report")
        open_report_button.set_action_name('app.open_report')
        toolbar.insert(open_report_button, 5)

        return toolbar

    def new_tab(self, scrolled_window):
        """The on_new_terminal_button redirects here. Tells the window
        to create pretty much a clone of itself when the user wants a new
        tab"""

        terminal = scrolled_window.get_children()[0]
        terminal.connect("child_exited", self.on_terminal_exit)
        self.tab_number += 1
        tab_number = self.tab_number
        pageN = self.terminalBox(scrolled_window)
        self.notebook.append_page(pageN, Gtk.Label(str(tab_number+1)))
        self.notebook.show_all()

    def delete_tab(self, button=None):
        """Deletes the current tab or closes the window if tab is only tab"""
        if self.tab_number == 0:
            # the following is confusing but its how gtks handles delete_event
            # if user said YES to confirmation, do_delete_event returns False
            if not self.do_delete_event():
                self.destroy()
        else:
            current_page = self.notebook.get_current_page()
            self.notebook.remove_page(current_page)
            self.reorder_tab_names()

    def reorder_tab_names(self):
        """When a tab is deleted, all other tabs must be renamed to reacomodate
        the numbers"""
        # Tabs are zero indexed, but their labels start at one

        number_of_tabs = self.notebook.get_n_pages()
        for n in range(number_of_tabs):
            tab = self.notebook.get_nth_page(n)
            self.notebook.set_tab_label_text(tab, str(n+1))
        self.tab_number = number_of_tabs-1

    def toggle_log(self, button):
        """Reverses the visibility status of the loggerbox"""
        current_state = self.loggerBox.is_visible()
        self.loggerBox.set_visible(not current_state)

    def do_delete_event(self, event=None, status=None):
        """Override delete_event signal to show a confirmation dialog first"""
        dialog = Gtk.MessageDialog(transient_for=self,
                                   modal=True,
                                   buttons=Gtk.ButtonsType.YES_NO)
        dialog.props.text = "Are you sure you want to quit Faraday?"
        response = dialog.run()
        dialog.destroy()

        if response == Gtk.ResponseType.YES:
            return False  # keep on going and destroy
        else:
            # user said "you know what i don't want to exit"
            return True

    def on_terminal_exit(self, terminal, status):
        """Really, it is *very* similar to delete_tab, but in this case
        we want to make sure that we restart Faraday is the user
        is not sure if he wants to exit"""

        self.delete_tab()
        terminal.startFaraday()
