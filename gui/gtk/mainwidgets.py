#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import gi
import os

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import Gtk, Gdk, Vte, GLib, Pango, GdkPixbuf


class Terminal(Vte.Terminal):
    """Defines a simple terminal that will execute faraday-terminal with the
    corresponding host and port as specified by the CONF"""
    def __init__(self, CONF):
        """Initialize terminal with infinite scrollback, no bell, connecting
        all keys presses to copy_or_past, and starting faraday-terminal
        """
        super(Vte.Terminal, self).__init__()
        self.set_scrollback_lines(-1)
        self.set_audible_bell(0)
        self.connect("key_press_event", self.copy_or_paste)
        self.host, self.port = CONF.getApiRestfulConInfo()

        faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))
        self.faraday_exec = faraday_directory + "/faraday-terminal.zsh"

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

    def copy_or_paste(self, widget, event):
        """Decides if the Ctrl+Shift is pressed, in which case returns True.
        If Ctrl+Shift+C or Ctrl+Shift+V are pressed, copies or pastes,
        acordingly. Return necesary so it doesn't perform other action,
        like killing the process on Ctrl+C.

        Note that it won't care about order: Shift+Ctrl+V will work just as
        Ctrl+Shift+V.
        """
        control_key = 'control-mask'
        shift_key = 'shift-mask'
        last_pressed_key = Gdk.keyval_name(event.get_keyval()[1])
        set_pressed_special_keys = set(event.state.value_nicks)
        if event.type == Gdk.EventType.KEY_PRESS:
            if {control_key, shift_key} <= set_pressed_special_keys:
                # '<=' means 'is a subset of' in sets
                if last_pressed_key == 'C':
                    self.copy_clipboard()
                elif last_pressed_key == 'V':
                    self.paste_clipboard()
                return True


class Sidebar(Gtk.Notebook):
    """Defines the bigger sidebar in a notebook. One of its tabs will contain
    the workspace view, listing all the workspaces (WorkspaceSidebar) and the
    other will contain the information about hosts, services, and vulns
    (HostsSidebar)
    """

    def __init__(self, workspace_sidebar, hosts_sidebar):
        """Attach to the notebok the workspace sidebar and the host_sidebar"""
        super(Gtk.Notebook, self).__init__()
        self.workspace_sidebar = workspace_sidebar
        self.hosts_sidebar = hosts_sidebar
        self.set_tab_pos(Gtk.PositionType.BOTTOM)

        self.append_page(self.workspace_sidebar, Gtk.Label("Workspaces"))
        self.append_page(self.hosts_sidebar, Gtk.Label("Hosts"))

    def get_box(self):
        box = Gtk.Box()
        box.pack_start(self, True, True, 0)
        return box


class HostsSidebar(Gtk.Widget):
    """Defines the widget displayed when the user is in the "Hosts" tab of
    the Sidebar notebook. Will list all the host, and when clicking on one,
    will open a window with more information about it"""

    def __init__(self, open_dialog_callback, icons):
        """Initializes the HostsSidebar. Initialization by itself does
        almost nothing, the application will inmediatly call create_model
        with the last workspace and create_view with that model upon startup.
        """
        super(Gtk.Widget, self).__init__()
        self.open_dialog_callback = open_dialog_callback
        self.current_model = None
        self.linux_icon = icons + "tux.png"
        self.windows_icon = icons + "windows.png"
        self.mac_icon = icons + "Apple.png"

    def create_model(self, hosts):
        """Creates a model for a lists of hosts. The model contians the
        host_id in the first column, the icon as a GdkPixbuf.Pixbuf()
        in the second column and a display_str with the host_name and the
        vulnerability count on the third column, like this:
        | HOST_ID | HOST_OS_PIXBUF   | OS_STR | DISPLAY_STR      | VULN_COUNT|
        ======================================================================
        | a923fd  | PixBufIcon(linux)| linux  | 192.168.1.2 (5)  |      5    |
        """
        def compute_vuln_count(host):
            """Return the total vulnerability count for a given host"""
            vuln_count = 0
            vuln_count += len(host.getVulns())
            for interface in host.getAllInterfaces():
                vuln_count += len(interface.getVulns())
                for service in interface.getAllServices():
                    vuln_count += len(service.getVulns())
            return vuln_count

        def decide_icon(os):
            """Return the GdkPixbuf icon according to 'os' paramather string
            and a str_id to that GdkPixbuf for easy comparison and ordering
            of the view ('os' paramether string is complicated and has caps).
            """
            os = os.lower()
            if "linux" in os or "unix" in os:
                icon = GdkPixbuf.Pixbuf.new_from_file(self.linux_icon)
                str_id = "linux"
            elif "windows" in os:
                icon = GdkPixbuf.Pixbuf.new_from_file(self.windows_icon)
                str_id = "windows"
            elif "mac" in os:
                icon = GdkPixbuf.Pixbuf.new_from_file(self.mac_icon)
                str_id = "mac"
            else:
                icon = None
                str_id = "unknown"
            return icon, str_id

        def compare_os_strings(model, an_os, other_os, user_data):
            """Compare an_os with other_os so the model knows how to sort them.
            user_data is not used.
            Forces 'unknown' OS to be always at the bottom of the model.
            Return values:
            1 means an_os should come after other_os
            0 means they are the same
            -1 means an_os should come before other_os
            It helps to think about it like the relative position of an_os
            in respect to other_os (-1 'left' in a list, 1 'right' in a list)
            """
            sort_column = 2
            an_os = model.get_value(an_os, sort_column)
            other_os = model.get_value(other_os, sort_column)
            if an_os == "unknown":
                order = 1
            elif an_os < other_os or other_os == "unknown":
                order = -1
            elif an_os == other_os:
                order = 0
            else:
                order = 1
            return order

        hosts_model = Gtk.ListStore(str, GdkPixbuf.Pixbuf(), str, str, int)

        for host in hosts:
            vuln_count = compute_vuln_count(host)
            os_icon, os_str = decide_icon(host.getOS())
            display_str = host.name + " (" + str(vuln_count) + ")"
            hosts_model.append([host.id, os_icon, os_str,
                                display_str, vuln_count])

        # sort the model by default according to column 4 (num of vulns)
        sorted_model = Gtk.TreeModelSort(model=hosts_model)
        sorted_model.set_sort_column_id(4, Gtk.SortType.DESCENDING)

        # set the sorting function of column 2
        sorted_model.set_sort_func(2, compare_os_strings, None)

        self.current_model = sorted_model

        return self.current_model

    def create_view(self, model):
        """Creates a view for the hosts model.
        It will contain two columns, the first with the OS icon given in
        the second column of the model. The second column of the view will
        be the string contained in the fourth column of the model.
        The first column of the view will be orderer according to the
        second column of the model, and the second column of the view will
        be ordered according to its fifth column.
        Will connect activation of a row with the on_click method
        """

        self.view = Gtk.TreeView(model)
        self.view.set_activate_on_single_click(True)

        text_renderer = Gtk.CellRendererText()
        icon_renderer = Gtk.CellRendererPixbuf()

        column_hosts = Gtk.TreeViewColumn("Hosts", text_renderer, text=3)
        column_hosts.set_sort_column_id(4)
        column_hosts.set_sort_indicator(True)

        column_os = Gtk.TreeViewColumn("", icon_renderer, pixbuf=1)
        column_os.set_sort_column_id(2)
        column_os.set_sort_indicator(True)

        self.view.append_column(column_os)
        self.view.append_column(column_hosts)


        self.view.connect("row_activated", self.on_click)

        self.view.set_enable_search(True)
        self.view.set_search_column(2)

        return self.view

    def update(self, hosts):
        """Creates a new model from an updated list of hosts and adapts
        the view to reflect the changes"""
        model = self.create_model(hosts)
        self.update_view(model)

    def update_view(self, model):
        """Updates the view of the object with a new model"""
        self.view.set_model(model)

    def on_click(self, tree_view, path, column):
        """Sends the host_id of the clicked host back to the application"""
        tree_iter = self.current_model.get_iter(path)
        host_id = self.current_model[tree_iter][0]
        self.open_dialog_callback(host_id)

    def get_box(self):
        """Returns the box to be displayed in the appwindow"""
        box = Gtk.Box()
        scrolled_view = Gtk.ScrolledWindow(None, None)
        scrolled_view.add(self.view)
        box.pack_start(scrolled_view, True, True, 0)
        return box


class WorkspaceSidebar(Gtk.Widget):
    """Defines the sidebar widget to be used by the AppWindow, passed as an
    instance to the application. It only handles the view and the model,
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

    def get_box(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.pack_start(self.getSearchEntry(), False, False, 0)
        box.pack_start(self.getScrollableView(), True, True, 0)
        box.pack_start(self.getButton(), False, False, 0)
        return box

    def createSearchEntry(self):
        """Returns a simple search entry"""
        searchEntry = Gtk.Entry()
        searchEntry.set_placeholder_text("Search...")
        searchEntry.connect("activate", self.onSearchEnterKey)
        return searchEntry

    def getSearchEntry(self):
        """Returns the search entry of the sidebar"""
        return self.searchEntry

    def getScrollableView(self):
        return self.scrollableView

    def onSearchEnterKey(self, entry):
        """When the users preses enter, if the workspace exists,
        select it. If not, present the window to create a workspace with
        that name"""
        selection = self.getSelectedWs()
        if selection.get_selected()[1] is None:
            self.callbackCreateWs(title=entry.get_text())
            entry.set_text("")
        else:
            self.callbackChangeWs(self.getSelectedWsName())
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
        """Creates and the workspace model. Also tries to assign
        self.defaultSelection to the treeIter which represents the last active workspace"""
        workspace_model = Gtk.ListStore(str)
        self.defaultSelection = None

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

            self.callbackChangeWs(self.getSelectedWsName())

        if event.button == 3:  # 3 represents right click
            menu = Gtk.Menu()
            delete_item = Gtk.MenuItem("Delete")
            menu.append(delete_item)

            # get tree_iter from path. then get its name. then delete
            # that workspace

            tree_iter = self.workspace_model.get_iter(path)
            ws_name = self.workspace_model[tree_iter][0]

            delete_item.connect("activate", self.callbackRemoveWs, ws_name)

            delete_item.show()
            menu.popup(None, None, None, None, event.button, event.time)
            return True  # prevents the click from selecting a workspace

    def change_label(self, new_label):
        self.sidebar_button.set_label(new_label)

    def restore_label(self):
        self.sidebar_button.set_label("Refresh workspaces")

    def addWorkspace(self, ws):
        """Append ws workspace to the model"""
        self.workspace_model.append([ws])

    def getSelectedWs(self):
        """Returns the selection of of the view.
        To retrieve the name, see getSelectedWsName"""
        selection = self.workspace_view.get_selection()
        return selection

    def getSelectedWsIter(self):
        """Returns the TreeIter of the current selected workspace"""
        selection = self.getSelectedWs()
        _iter = selection.get_selected()[1]
        return _iter

    def getSelectedWsName(self):
        """Return the name of the selected workspace"""
        selection = self.getSelectedWs()
        tree_model, treeiter = selection.get_selected()
        workspaceName = tree_model[treeiter][0]
        return workspaceName

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
        """Filters event so that only those with type 3131 get to the log.
        Also split them, so we can add the correct formatting to the first
        part of the message"""

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
        self.notif_button.connect("clicked", self.set_default_notif_label)

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

    def set_default_notif_label(self, button=None):
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
