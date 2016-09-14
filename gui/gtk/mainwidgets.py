#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import gi
import os
import math

gi.require_version('Gtk', '3.0')

try:
    gi.require_version('Vte', '2.91')
except ValueError:
    gi.require_version('Vte', '2.90')

from gi.repository import Gtk, Gdk, GLib, Pango, GdkPixbuf, Vte

from decorators import scrollable
from compatibility import CompatibleVteTerminal as VteTerminal
from compatibility import CompatibleScrolledWindow as GtkScrolledWindow


class Terminal(VteTerminal):
    """Defines a simple terminal that will execute faraday-terminal with the
    corresponding host and port as specified by the CONF.
    Inherits from Compatibility.Vte, which is just Vte.Terminal with
    spawn_sync overrode to function with API 2.90 and 2.91"""

    def __init__(self, CONF):
        """Initialize terminal with infinite scrollback, no bell, connecting
        all keys presses to copy_or_past, and starting faraday-terminal
        """
        VteTerminal.__init__(self)
        self.set_scrollback_lines(-1)
        self.set_audible_bell(0)
        self.connect("key_press_event", self.copy_or_paste)
        self.host, self.port = CONF.getApiRestfulConInfo()

        faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))
        self.faraday_exec = faraday_directory + "/faraday-terminal.zsh"

        self.start_faraday()

    @scrollable(overlay_scrolling=True)
    def create_scrollable_terminal(self):
        """Returns a scrolled_window with the terminal inside it thanks
        to the scrollable decorator."""
        return self

    def start_faraday(self):
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

    def box_it(self):
        """Wraps the notebook inside a little box."""
        box = Gtk.Box()
        box.pack_start(self, True, True, 0)
        return box


class HostsSidebar(Gtk.Widget):
    """Defines the widget displayed when the user is in the "Hosts" tab of
    the Sidebar notebook. Will list all the host, and when clicking on one,
    will open a window with more information about it"""

    def __init__(self, open_dialog_callback, get_host_function, icons):
        """Initializes the HostsSidebar. Initialization by itself does
        almost nothing, the application will inmediatly call create_model
        with the last workspace and create_view with that model upon startup.
        """
        Gtk.Widget.__init__(self)
        self.open_dialog_callback = open_dialog_callback
        self.get_host_function = get_host_function
        self.current_model = None
        self.progress_label = Gtk.Label("")
        self.host_amount = 0
        self.page = 0
        self.host_id_to_iter = {}
        self.linux_icon = icons + "tux.png"
        self.windows_icon = icons + "windows.png"
        self.mac_icon = icons + "Apple.png"
        self.no_os_icon = icons + "TreeHost.png"

    def __compute_vuln_count(self, host):
        """Return the total vulnerability count for a given host"""
        return host.getVulnAmount()

    def __get_vuln_amount_from_model(self, host_id):
        """Given a host_id, it will look in the current model for the host_id
        and return the amount of vulnerabilities IF the host_id corresponds
        to the model ID. Else it will return None.
        """
        host_iter = self.host_id_to_iter.get(host_id)
        if host_iter:
            return self.current_model[host_iter][4]

    def __add_host_to_model(self, host):
        """Adds host to the model given as parameter in the initial load
        of the sidebar."""
        vuln_count = self.__compute_vuln_count(host)
        os_icon, os_str = self.__decide_icon(host.getOS())
        display_str = str(host)
        host_iter = self.current_model.append([host.id, os_icon, os_str,
                                               display_str, vuln_count])
        self.host_id_to_iter[host.id] = host_iter

    def __add_host_to_model_after_initial_load(self, host):
        """Adds a host to the model after the intial load is done
        (host came through the changes or through a plugin)"""
        self.host_amount += 1
        if self.host_amount % 20 == 0:
            self.redo([host], self.host_amount, page=self.page+1)
        else:
            self.__add_host_to_model(host)

    def __host_exists_in_current_model(self, host_id):
        return self.host_id_to_iter.get(host_id) is not None

    def __get_host_from_host_id(self, host_id):
        try:
            return self.get_host_function(couchid=host_id)[0]
        except IndexError:
            return None

    def __add_vuln_to_model(self, vuln):
        """When a new vulnerability arrives, look up its hosts
        and update its vuln amount and its representation as a string."""
        host_id = self.__find_host_id(vuln)
        if self.__host_exists_in_current_model(host_id):
            real_host = self.__get_host_from_host_id(host_id)
            if real_host is None: return
            vuln_amount = self.__compute_vuln_count(real_host)
            self.__update_host_str(host_id, new_vuln_amount=vuln_amount)

    def __remove_vuln_from_model(self, host_id):
        """When a new vulnerability id deleted, look up its hosts
        fand update its vuln amount and its representation as a string."""
        if self.__host_exists_in_current_model(host_id):
            real_host = self.__get_host_from_host_id(host_id)
            if real_host is None: return
            vuln_amount = self.__compute_vuln_count(real_host)
            self.__update_host_str(host_id, new_vuln_amount=vuln_amount)

    def __update_host_str(self, host_id, new_vuln_amount=None, new_host_name=None):
        """When a new vulnerability id deleted, look up its hosts
        and update its vuln amount and its representation as a string."""
        host_iter = self.host_id_to_iter[host_id]
        if not new_host_name:
            new_host_name = str(self.current_model[host_iter][3].split(" ")[0])
        if new_vuln_amount is None:
            new_vuln_amount = str(self.current_model[host_iter][4])
        new_string = "{0} ({1})".format(new_host_name, new_vuln_amount)
        self.current_model.set_value(host_iter, 3, new_string)
        self.current_model.set_value(host_iter, 4, int(new_vuln_amount))

    def __update_host_in_model(self, host):
        self.__update_host_str(host.getID(), new_host_name=host.getName())

    def __remove_host_from_model(self, host_id):
        """Deletes a host from the model given as parameter."""
        if self.__host_exists_in_current_model(host_id):
            host_iter = self.host_id_to_iter[host_id]
            could_be_removed = self.current_model.remove(host_iter)
            del self.host_id_to_iter[host_id]
        else:
            could_be_removed = False
        return could_be_removed

    def __find_host_id(self, object_info):
        object_id = object_info.getID()
        host_id = object_id.split(".")[0]
        return host_id

    def __decide_icon(self, os):
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
            icon = GdkPixbuf.Pixbuf.new_from_file(self.no_os_icon)
            str_id = "unknown"
        return icon, str_id

    def create_model(self, hosts):
        """Creates a model for a lists of hosts. The model contians the
        host_id in the first column, the icon as a GdkPixbuf.Pixbuf()
        in the second column and a display_str with the host_name and the
        vulnerability count on the third column, like this:
        | HOST_ID | HOST_OS_PIXBUF   | OS_STR | DISPLAY_STR      | VULN_COUNT|
        ======================================================================
        | a923fd  | PixBufIcon(linux)| linux  | 192.168.1.2 (5)  |      5    |
        """

        hosts_model = Gtk.ListStore(str, GdkPixbuf.Pixbuf(), str, str, int)
        self.current_model = hosts_model
        for host in hosts:
            self.__add_host_to_model(host)

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
        self.view.set_activate_on_single_click(False)

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

    def add_object(self, obj):
        object_type = obj.class_signature
        if object_type == 'Host':
            self.__add_host_to_model_after_initial_load(obj)
        if object_type == "Vulnerability" or object_type == "VulnerabilityWeb":
            self.__add_vuln_to_model(obj)

    def remove_object(self, obj_id):
        if obj_id.count('.') == 0:
            self.__remove_host_from_model(obj_id)
        else:
            host_id = obj_id.split(".")[0]
            self.__remove_vuln_from_model(host_id)

    def update_object(self, obj):
        object_type = obj.class_signature
        if object_type == 'Host':
            self.__update_host_in_model(obj)

    def redo(self, hosts, total_host_amount, page=0):
        """Creates a new model from an updated list of hosts and adapts
        the view to reflect the changes"""
        self.page = page
        self.host_id_to_iter = {}
        model = self.create_model(hosts)
        self.redo_view(model)
        self.host_amount = total_host_amount
        self.set_move_buttons_sensitivity()
        self.progress_label.set_label("{0} / {1}".format(self.page+1, self.compute_total_number_of_pages()+1))

    def redo_view(self, model):
        """Updates the view of the object with a new model"""
        self.view.set_model(model)
        self.progress_label.set_label("{0} / {1}".format(self.page+1, self.compute_total_number_of_pages()+1))

    def on_click(self, tree_view, path, column):
        """Sends the host_id of the clicked host back to the application"""
        tree_iter = self.current_model.get_iter(path)
        host_id = self.current_model[tree_iter][0]
        self.open_dialog_callback(host_id)

    def set_move_buttons_sensitivity(self):
        if self.page > 0:
            self.prev_button.set_sensitive(True)
        else:
            self.prev_button.set_sensitive(False)
        if self.compute_total_number_of_pages() > self.page:
            self.next_button.set_sensitive(True)
        else:
            self.next_button.set_sensitive(False)

    def compute_total_number_of_pages(self):
        return int(math.ceil(self.host_amount / 20))

    @scrollable(width=160)
    def scrollable_view(self):
        return self.view

    def get_box(self):
        search_entry= self.create_search_entry()
        scrollable_view = self.scrollable_view()
        button_box = self.button_box()
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar_box.pack_start(search_entry, False, False, 0)
        sidebar_box.pack_start(scrollable_view, True, True, 0)
        sidebar_box.pack_start(button_box, False, True, 0)
        return sidebar_box

    def button_box(self):
        button_box = Gtk.Box()
        button_box.override_background_color(Gtk.StateType.NORMAL, Gdk.RGBA(.1,.1,.1,.1))
        self.prev_button = Gtk.Button.new_with_label("<<")
        self.next_button = Gtk.Button.new_with_label(">>")
        self.prev_button.connect("clicked", self.on_click_move_page, lambda x: x-1)
        self.next_button.connect("clicked", self.on_click_move_page, lambda x: x+1)
        button_box.pack_start(self.prev_button, True, True, 0)
        button_box.pack_start(self.progress_label, True, True, 0)
        button_box.pack_start(self.next_button, True, True, 0)
        return button_box

    def on_click_move_page(self, button, add_one_or_take_one_from, *args, **kwargs):
        self.page = add_one_or_take_one_from(self.page)
        hosts = self.get_host_function(page=str(self.page), page_size=20,
                                       sort='vulns', sort_dir='desc')
        model = self.create_model(hosts)
        self.redo_view(model)
        self.set_move_buttons_sensitivity()

    def create_search_entry(self):
        """Returns a simple search entry"""
        search_entry = Gtk.Entry()
        search_entry.set_placeholder_text("Search a host by name...")
        search_entry.connect("activate", self.on_search_enter_key)
        search_entry.show()
        return search_entry

    def on_search_enter_key(self, entry):
        """When the users preses enter, if the workspace exists,
        select it. If not, present the window to create a workspace with
        that name"""
        search = entry.get_text()
        if search == "":
            hosts = self.get_host_function(page=0, page_size=20, sort='vulns',
                                           sort_dir='desc')
            model = self.create_model(hosts)
            self.redo_view(model)
            self.set_move_buttons_sensitivity()
        else:
            hosts = self.get_host_function(name=search, sort='name',
                                           sort_dir='desc')
            model = self.create_model(hosts)
            self.redo_view(model)
            self.prev_button.set_sensitive(False)
            self.next_button.set_sensitive(False)


class WorkspaceSidebar(Gtk.Widget):
    """Defines the sidebar widget to be used by the AppWindow, passed as an
    instance to the application. It only handles the view and the model,
    all the backend word is handled by the application via the callback"""

    def __init__(self, server_io, callback_to_change_workspace,
                 callback_to_remove_workspace, callback_to_create_workspace,
                 last_workspace):

        Gtk.Widget.__init__(self)
        self.change_ws = callback_to_change_workspace
        self.remove_ws = callback_to_remove_workspace
        self.create_ws = callback_to_create_workspace
        self.last_workspace = last_workspace
        self.serverIO = server_io

        self.workspaces = self.serverIO.get_workspaces_names()
        self.search_entry = self.create_search_entry()

        self.workspace_model = self.create_ws_model()
        self.workspace_view = self.create_ws_view(self.workspace_model)

        self.sidebar_button = Gtk.Button.new_with_label("Refresh workspaces")
        self.sidebar_button.connect("clicked", self.refresh_sidebar)

    def get_box(self):
        """Creates a return a simple vertical box containing all the widgets
        that make the sidebar.
        """
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        box.pack_start(self.search_entry, False, False, 0)
        box.pack_start(self.workspace_view, True, True, 0)
        box.pack_start(self.sidebar_button, False, False, 0)
        return box

    def create_search_entry(self):
        """Returns a simple search entry"""
        search_entry = Gtk.Entry()
        search_entry.set_placeholder_text("Search...")
        search_entry.connect("activate", self.on_search_enter_key)
        return search_entry

    def on_search_enter_key(self, entry):
        """When the users preses enter, if the workspace exists,
        select it. If not, present the window to create a workspace with
        that name"""
        selection = self.ws_view.get_selection()
        model, ws_iter = selection.get_selected()

        if ws_iter is None:
            self.create_ws(title=entry.get_text())
            entry.set_text("")
        else:
            self.change_ws(self.get_selected_ws_name())
            ws_iter = self.get_selected_ws_iter()
            entry.set_text("")
            self.select_ws_by_iter(ws_iter)

    def refresh_sidebar(self, button=None):
        """Function called when the user press the refresh button.
        Gets an updated copy of the workspaces and checks against
        the model to see which are already there and which arent"""

        self.workspaces = self.serverIO.get_workspaces_names()

        model = self.workspace_model
        added_workspaces = [added_ws[0] for added_ws in model]
        for ws in self.workspaces:
            if ws not in added_workspaces:
                ws_iter = self.workspace_model.append([ws])
                self.valid_ws_iters.append(ws_iter)

    def clear_sidebar(self):
        """Brutaly clear all the information from the model.
        No one survives"""
        self.valid_ws_iters = []
        self.workspace_model.clear()

    def create_ws_model(self):
        """Creates and the workspace model. Also tries to assign
        self.default_selection to the tree_iter which represents the
        last active workspace"""
        workspace_model = Gtk.ListStore(str)
        self.default_selection = None
        self.valid_ws_iters = []

        for ws in self.workspaces:
            tree_iter = workspace_model.append([ws])
            self.valid_ws_iters.append(tree_iter)
            if ws == self.last_workspace:
                self.default_selection = tree_iter

        return workspace_model

    @scrollable(width=160)
    def create_ws_view(self, model):
        """Populate the workspace view. Also select by default
        self.default_selection (see workspace_model method). Also connect
        a selection with the change workspace callback"""

        self.ws_view = Gtk.TreeView(model)
        self.ws_view.set_activate_on_single_click(False)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Workspaces", renderer, text=0)
        self.ws_view.append_column(column)
        self.ws_view.set_search_entry(self.search_entry)

        # select by default the last active workspace
        if self.default_selection is not None:
            self.select_default = self.ws_view.get_selection()
            self.select_default.select_iter(self.default_selection)

        selection = self.ws_view.get_selection()
        selection.set_mode(Gtk.SelectionMode.BROWSE)

        self.ws_view.connect("button-press-event", self.on_right_click)
        self.ws_view.connect("row-activated", self.on_left_click)

        return self.ws_view

    def on_left_click(self, view, path, column):

        # force selection of newly selected
        # before actually changing workspace
        select = view.get_selection()
        select.select_path(path)

        # change the workspace to the newly selected
        self.change_ws(self.get_selected_ws_name())
        return True # prevents the click from selecting a workspace
                    # this is handled manually by us on self.change_ws

    def on_right_click(self, view, event):
        """On click, check if it was a right click. If it was,
        create a menu with the delete option. On click on that option,
        delete the workspace that occupied the position where the user
        clicked. Returns True if it was a right click"""

        # if it isnt right click just do nothing
        if event.button != 3:
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

        menu = Gtk.Menu()
        delete_item = Gtk.MenuItem("Delete")
        menu.append(delete_item)

        # get tree_iter from path. then get its name. then delete
        # that workspace

        tree_iter = self.workspace_model.get_iter(path)
        ws_name = self.workspace_model[tree_iter][0]

        delete_item.connect("activate", self.remove_ws, ws_name)

        delete_item.show()
        menu.popup(None, None, None, None, event.button, event.time)
        return True  # prevents the click from selecting a workspace

    def get_selected_ws_iter(self):
        """Returns the tree_iter of the current selected workspace"""
        selection = self.ws_view.get_selection()
        _iter = selection.get_selected()[1]
        return _iter

    def get_selected_ws_name(self):
        """Return the name of the selected workspace"""
        selection = self.ws_view.get_selection()
        model, ws_iter = selection.get_selected()
        workspace_name = model[ws_iter][0]
        return workspace_name

    def select_ws_by_iter(self, ws_iter):
        """Selects workspace of iter ws_iter in the list"""
        selection = self.ws_view.get_selection()
        selection.select_iter(ws_iter)

    def get_iter_by_name(self, ws_name):
        """Returns the iter associated to the workspace ws_name or None
        if not found.
        """
        for ws_iter in self.valid_ws_iters:
            if self.workspace_model[ws_iter][0] == ws_name:
                return ws_iter
        else:
            return None

    def select_ws_by_name(self, ws_name):
        """Selects the workspace by name ws_name"""
        ws_iter = self.get_iter_by_name(ws_name)
        if ws_iter is not None:
            self.select_ws_by_iter(ws_iter)

    def add_workspace(self, ws):
        """Adds a workspace to the model and to the list of valid iters."""
        ws_iter = self.workspace_model.append([ws])
        self.valid_ws_iters.append(ws_iter)


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

        self.textBuffer.set_text("Welcome to Faraday!\n\0",
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

    @scrollable(height=100, width=100)
    def create_scrollable_logger(self):
        """Returns the ScrolledWindow used to contain the view"""
        return self.textView

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
    """Defines a statusbar. Will have a notifications button,
    a string informing of how many hosts/services/vulns are in the
    current workspace nad the conflicts button."""

    def __init__(self, notif_callback, conflict_callback,
                 host_count, service_count, vuln_count):
        """Initializes the statusbar. Takes a notification_callback
        to open the notifiacion window, conflick_callback to open
        the conclifcts window, and a host, service and vuln counts
        to be displayed"""
        Gtk.Widget.__init__(self)
        initial_strings = self.create_strings(host_count, service_count,
                                              vuln_count)

        self.active_workspace_label = Gtk.Label()
        self.active_workspace_label.set_use_markup(True)
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
        self.mainBox.pack_start(Gtk.Box(), True, True, 5)  # blank space
        self.mainBox.pack_start(self.active_workspace_label, False, True, 5)
        self.mainBox.pack_end(self.conflict_button, False, True, 5)

    def set_workspace_label(self, new_label):
        self.active_workspace_label.set_label("Active workspace: <b>{0}</b>".format(new_label))

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
