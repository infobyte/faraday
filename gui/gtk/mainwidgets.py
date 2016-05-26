#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import gi
import os
import sys

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import Gtk, Vte, GLib, Pango


class Terminal(Vte.Terminal):
    """Defines a simple terminal that will execute faraday-terminal with the
    corresponding host and port as specified by the CONF"""
    def __init__(self, CONF):
        super(Vte.Terminal, self).__init__()

        self.pty = self.pty_new_sync(Vte.PtyFlags.DEFAULT, None)
        self.set_pty(self.pty)

        self.set_scrollback_lines(-1)
        self.set_audible_bell(0)

        self.faraday_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.host, self.port = CONF.getApiRestfulConInfo()
        self.faraday_exec = self.faraday_directory + "/faraday-terminal.zsh"

        self.startFaraday()

    def getTerminal(self):
        """Returns a scrolled_window with the terminal inside it"""
        scrolled_window = Gtk.ScrolledWindow.new(None, None)
        scrolled_window.set_overlay_scrolling(False)
        scrolled_window.add(self)
        return scrolled_window

    def startFaraday(self):
        """Starts a Faraday process with the appropiate host and port."""

        home_dir = os.path.expanduser('~')
        self.spawn_sync(Vte.PtyFlags.DEFAULT,
                        home_dir,
                        [self.faraday_exec, str(self.host), str(self.port)],
                        [],
                        GLib.SpawnFlags.DO_NOT_REAP_CHILD,
                        None,
                        None)


class Sidebar(Gtk.Widget):
    """Defines the sidebar widget to be used by the AppWindow, passed as an
    instance to itby the application. It only handles the view and the model,
    all the backend word is handled by the application via the callback"""

    def __init__(self, workspace_manager, callback_to_change_workspace,
                 callback_to_remove_workspace, callback_to_create_workspace,
                 last_workspace):

        super(Gtk.Widget, self).__init__()
        self.callbackChangeWs = callback_to_change_workspace
        self.callbackRemoveWs = callback_to_remove_workspace
        self.callbackCreateWs = callback_to_create_workspace
        self.lastWorkspace = last_workspace
        self.ws_manager = workspace_manager

        self.workspaces = self.ws_manager.getWorkspacesNames()
        self.searchEntry = self.createSearchEntry()

        self.workspace_model = self.createWsModel()
        self.workspace_view = self.createWsView(self.workspace_model)

        self.sidebar_button = Gtk.Button.new_with_label("Refresh workspaces")
        self.sidebar_button.connect("clicked", self.refreshSidebar)

        self.scrollableView = Gtk.ScrolledWindow.new(None, None)
        self.scrollableView.set_min_content_width(160)
        self.scrollableView.add(self.workspace_view)

    def createSearchEntry(self):
        """Returns a simple search entry"""
        searchEntry = Gtk.Entry()
        searchEntry.set_placeholder_text("Search...")
        searchEntry.connect("activate", self.onSearchEnterKey)
        return searchEntry

    def getSearchEntry(self):
        """Returns the search entry of the sidebar"""
        return self.searchEntry

    def onSearchEnterKey(self, entry):
        """When the users preses enter, if the workspace exists,
        select it. If not, present the window to create a workspace with
        that name"""
        selection = self.getSelectedWs()
        if selection.get_selected()[1] is None:
            self.callbackCreateWs(title=entry.get_text())
            entry.set_text("")
        else:
            self.callbackChangeWs(selection)
            ws_iter = self.getSelectedWsIter()
            entry.set_text("")
            self.selectWs(ws_iter)

    def refreshSidebar(self, button=None):
        """Function called when the user press the refresh button.
        Gets an updated copy of the workspaces and checks against
        the model to see which are already there and which arent"""

        model = self.workspace_model
        self.workspaces = self.ws_manager.getWorkspacesNames()
        added_workspaces = [added_ws[0] for added_ws in model]
        for ws in self.workspaces:
            if ws not in added_workspaces:
                self.addWorkspace(ws)

    def clearSidebar(self):
        """Brutaly clear all the information from the model.
        No one survives"""
        self.workspace_model.clear()

    def createWsModel(self):
        """Creates and the workspace model. Also assigns self.defaultSelection
        to the treeIter which represents the last active workspace"""
        workspace_model = Gtk.ListStore(str)

        for ws in self.workspaces:
            treeIter = workspace_model.append([ws])
            if ws == self.lastWorkspace:
                self.defaultSelection = treeIter

        return workspace_model

    def createWsView(self, model):
        """Populate the workspace view. Also select by default
        self.defaultSelection (see workspaceModel method). Also connect
        a selection with the change workspace callback"""

        view = Gtk.TreeView(model)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Workspaces", renderer, text=0)
        view.append_column(column)
        view.set_search_entry(self.searchEntry)

        # select by default the last active workspace
        if self.defaultSelection is not None:
            self.selectDefault = view.get_selection()
            self.selectDefault.select_iter(self.defaultSelection)

        selection = view.get_selection()
        selection.set_mode(Gtk.SelectionMode.BROWSE)

        view.connect("button-press-event", self.on_click)

        return view

    def on_click(self, view, event):
        """On click, check if it was a right click. If it was,
        create a menu with the delete option. On click on that option,
        delete the workspace that occupied the position where the user
        clicked. Returns True if it was a right click"""

        # it it isnt right click or left click just do nothing
        if event.button != 3 and event.button != 1:
            return False

        # we really do care about where the user clicked, that is our
        # connection to the soon to be selection. if this didn't exist,
        # we couldn't do much: the selection of the view is still
        # whatever the user had selected before clicking
        try:
            path = view.get_path_at_pos(int(event.x), int(event.y))[0]
        except TypeError:
            # if the user didn't click on a workspace there no path to work on
            return False

        # left click:
        if event.button == 1:
            # force selection of newly selected
            # before actually changing workspace
            select = view.get_selection()
            select.select_path(path)

            # change the workspace to the newly selected
            self.callbackChangeWs(self.getSelectedWs())

        if event.button == 3:  # 3 represents right click
            menu = Gtk.Menu()
            delete_item = Gtk.MenuItem("Delete")
            menu.append(delete_item)

            # get the path of the item where the user clicked
            # then get its tree_iter. then get its name. then delete
            # that workspace

            tree_iter = self.workspace_model.get_iter(path)
            ws_name = self.workspace_model[tree_iter][0]

            delete_item.connect("activate", self.callbackRemoveWs, ws_name)

            delete_item.show()
            menu.popup(None, None, None, None, event.button, event.time)
            return True  # prevents the click from selecting a workspace

    def addWorkspace(self, ws):
        """Append ws workspace to the model"""
        self.workspace_model.append([ws])

    def getSelectedWs(self):
        """Returns the name of the current selected workspace"""
        selection = self.workspace_view.get_selection()
        return selection

    def getSelectedWsIter(self):
        """Returns the TreeIter of the current selected workspace"""
        selection = self.getSelectedWs()
        _iter = selection.get_selected()[1]
        return _iter

    def selectWs(self, ws):
        """Selects workspace ws in the list"""
        self.select = self.workspace_view.get_selection()
        self.select.select_iter(ws)

    def getButton(self):
        """Returns the refresh sidebar button"""
        return self.sidebar_button


class ConsoleLog(Gtk.Widget):
    """Defines a textView and a textBuffer to be used for displaying
    and updating logging information in the appwindow."""

    def __init__(self):
        super(Gtk.Widget, self).__init__()

        self.textBuffer = Gtk.TextBuffer()
        self.textBuffer.new()

        self.red = self.textBuffer.create_tag("error", foreground='Red')
        self.green = self.textBuffer.create_tag("debug", foreground='Green')
        self.blue = self.textBuffer.create_tag("notif", foreground="Blue")
        self.orange = self.textBuffer.create_tag("warning",
                                                 foreground="#F5760F")
        self.bold = self.textBuffer.create_tag("bold",
                                               weight=Pango.Weight.BOLD)

        self.textBuffer.set_text("Welcome to Faraday. Happy hacking!\n\0",
                                 -1)

        self.textBuffer.apply_tag(self.bold,
                                  self.textBuffer.get_iter_at_line(0),
                                  self.textBuffer.get_end_iter())

        self.textView = Gtk.TextView()
        self.textView.set_editable(False)
        # TODO: only execute monospace if Gi >= 3.16
        # self.textView.set_monospace(True)
        self.textView.set_justification(Gtk.Justification.LEFT)

        self.textView.set_buffer(self.textBuffer)

        self.logger = Gtk.ScrolledWindow.new(None, None)
        self.logger.set_min_content_height(100)
        self.logger.set_min_content_width(100)
        self.logger.add(self.textView)

    def getLogger(self):
        """Returns the ScrolledWindow used to contain the view"""
        return self.logger

    def getView(self):
        """Returns the text view"""
        return self.textView

    def getBuffer(self):
        """Returns the buffer"""
        return self.textBuffer

    def customEvent(self, text):
        """Filters event so that only those with type 3131 get to the log"""
        text = text.split('-')
        if text[0] == "INFO ":
            self.update("[ " + text[0] + "]", self.bold)
        if text[0] == "DEBUG ":
            self.update("[ " + text[0] + "]", self.bold, self.green)
        if text[0] == "ERROR " or text[0] == "CRITICAL: ":
            self.update("[ " + text[0] + "]", self.bold, self.red)
        if text[0] == "WARNING ":
            self.update("[ " + text[0] + "]", self.bold, self.orange)
        if text[0] == "NOTIFICATION ":
            self.update("[ " + text[0] + "]", self.bold, self.blue)

        self.update("-" + '-'.join(text[1:]) + "\n")

    def update(self, text, *tags):
        """Updates the textBuffer with the event sent. Also scrolls to last
        posted automatically"""
        last_position = self.textBuffer.get_end_iter()
        self.textBuffer.insert(last_position, text, len(text))

        # we need to take 1 from the lines to compensate for the default line
        lines = self.textBuffer.get_line_count()
        begin = self.textBuffer.get_iter_at_line(lines-1)

        # update last position, it isn't the same as when the funcion started
        last_position = self.textBuffer.get_end_iter()

        for tag in tags:
            self.textBuffer.apply_tag(tag, begin, last_position)

        self.scroll_to_insert(self.textBuffer.get_insert())

    def scroll_to_insert(self, insert):
        """Scrolls the view to a particular insert point"""
        self.textView.scroll_to_mark(insert, 0, False, 1, 1)


class Statusbar(Gtk.Widget):
    """Defines a statusbar, which is actually more quite like a button.
    The button has a label that tells how many notifications are there.
    Takes an on_button_do callback, so it can tell the application what
    to do when the user presses the button"""

    def __init__(self, notif_callback, conflict_callback,
                 host_count, service_count, vuln_count):
        super(Gtk.Widget, self).__init__()
        """Initialices a button with a label on zero"""
        initial_strings = self.create_strings(host_count, service_count,
                                              vuln_count)
        self.notif_text = "Notifications: "
        self.conflict_text = "Conflicts: "

        self.host_count_str = initial_strings[0]
        self.service_count_str = initial_strings[1]
        self.vuln_count_str = initial_strings[2]

        self.ws_info = self.create_initial_ws_info()

        self.notif_button = Gtk.Button.new()
        self.set_default_notif_label()
        self.notif_button.connect("clicked", notif_callback)

        self.conflict_button = Gtk.Button.new()
        self.set_default_conflict_label()
        self.conflict_button.connect("clicked", conflict_callback)

        self.mainBox = Gtk.Box()
        self.mainBox.pack_start(self.notif_button, False, False, 5)
        self.mainBox.pack_start(self.ws_info, False, True, 5)
        self.mainBox.pack_start(Gtk.Box(), True, True, 5)  # space
        self.mainBox.pack_end(self.conflict_button, False, True, 0)

    def inc_notif_button_label(self):
        """Increments the button label, sets bold so user knows there are
        unread notifications"""

        self.notif_button_label_int += 1
        child = self.notif_button.get_child()
        self.notif_button.remove(child)
        label = Gtk.Label.new()
        label.set_markup("<b> %s %s </b>"
                         % (self.notif_text, str(self.notif_button_label_int)))

        label.show()
        self.notif_button.add(label)

    def update_conflict_button_label(self, n):
        self.conflict_button_label_int += n
        child = self.conflict_button.get_child()
        self.conflict_button.remove(child)
        label = Gtk.Label.new(self.conflict_text +
                              str(self.conflict_button_label_int))
        label.show()
        self.conflict_button.add(label)

    def set_default_notif_label(self):
        """Creates the default label"""
        self.notif_button_label_int = 0
        self.notif_button.set_label(self.notif_text +
                                    str(self.notif_button_label_int))

    def set_default_conflict_label(self):
        self.conflict_button_label_int = 0
        self.conflict_button.set_label(self.conflict_text +
                                       str(self.conflict_button_label_int))

    def create_initial_ws_info(self):
        box = Gtk.Box()
        self.explain = Gtk.Label.new("Workspace status: ")
        self.host_label = Gtk.Label.new(self.host_count_str)
        self.service_label = Gtk.Label.new(self.service_count_str)
        self.vuln_label = Gtk.Label.new(self.vuln_count_str)

        box.pack_start(self.explain, True, True, 0)
        box.pack_start(self.host_label, True, True, 0)
        box.pack_start(self.service_label, True, True, 0)
        box.pack_start(self.vuln_label, True, True, 0)
        return box

    def update_ws_info(self, new_host_count, new_service_count,
                       new_vuln_count):

        host, service, vuln = self.create_strings(new_host_count,
                                                  new_service_count,
                                                  new_vuln_count)
        self.host_label.set_text(host)
        self.service_label.set_text(service)
        self.vuln_label.set_text(vuln)

    def create_strings(self, host_count, service_count, vuln_count):
        host_string = str(host_count) + " hosts, "
        service_string = str(service_count) + " services, "
        vuln_string = str(vuln_count) + " vulnerabilities."

        return host_string, service_string, vuln_string
