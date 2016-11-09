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
import operator
import webbrowser

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

    def __init__(self, open_dialog_callback, get_several_hosts_function,
                 get_single_host_function, icons):
        """Initializes the HostsSidebar. Initialization by itself does
        almost nothing, the application will inmediatly call create_model
        with the last workspace and create_view with that model upon startup.

        The model looks like this:
        | HOST_ID | HOST_OS_PIXBUF   | OS_STR | DISPLAY_STR      | VULN_COUNT|
        ======================================================================
        | a923fd  | PixBufIcon(linux)| linux  | 192.168.1.2 (5)  |      5    |
        """

        Gtk.Widget.__init__(self)
        self.open_dialog_callback = open_dialog_callback
        self.get_hosts_function = get_several_hosts_function
        self.get_single_host_function = get_single_host_function
        self.model = Gtk.ListStore(str, GdkPixbuf.Pixbuf(), str, str, int)
        self.create_view()
        self.progress_label = Gtk.Label("")
        self.host_amount_total = 0
        self.host_amount_in_model = 0
        self.page = 0
        self.host_id_to_iter = {}
        self.linux_icon = icons + "tux.png"
        self.windows_icon = icons + "windows.png"
        self.mac_icon = icons + "Apple.png"
        self.no_os_icon = icons + "TreeHost.png"

    @property
    def number_of_pages(self):
        return int(math.ceil(float(self.host_amount_total) / 20))

    @scrollable(width=160)
    def scrollable_view(self):
        return self.view

    def create_view(self):
        """Creates a view for the hosts model.
        It will contain two columns, the first with the OS icon given in
        the second column of the model. The second column of the view will
        be the string contained in the fourth column of the model.
        The first column of the view will be orderer according to the
        second column of the model, and the second column of the view will
        be ordered according to its fifth column.
        Will connect activation of a row with the on_click method
        """
        self.view = Gtk.TreeView(self.model)
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

    def reset_model(self, hosts):
        """Resets the model to a new list of hosts.
        Use for changing of pages, _not_ for changing of workspaces,
        there's reset_model_after_workspace_changed for that.
        """
        self.model.clear()
        self.host_amount_in_model = 0
        self.host_id_to_iter = {}
        self.add_relevant_hosts_to_model(hosts)
        self.set_move_buttons_sensitivity()

    def reset_model_after_workspace_changed(self, hosts, total_host_amount):
        """Reset the model and also sets the page to 0 and the new total
        host amount will be the length of host."""
        self.page = 0
        self.host_amount_total = total_host_amount
        self.reset_model(hosts)
        self.update_progress_label()

    def __decide_icon(self, os):
        """Return the GdkPixbuf icon according to 'os' paramather string
        and a str_id to that GdkPixbuf for easy comparison and ordering
        of the view ('os' paramether string is complicated and has caps).
        """
        os = os.lower() if os else ""
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

    def _find_host_id(self, object_):
        """Return the ID of the object's parent host."""
        object_id = object_.getID()
        host_id = object_id.split(".")[0]
        return host_id

    def _is_host_in_model_by_host_id(self, host_id):
        """Return a boolean indicating if host_id is in the model"""
        return self.host_id_to_iter.get(host_id) is not None

    def _get_vuln_amount_from_model(self, host_iter):
        """Return the amount of vulns the model thinks host_iter has.

        @preconditions: host_iter in self.model
        """
        return self.model[host_iter][4]

    def _vulns_ids_of_host(self, host):
        """Return a list of vulnerabilities IDs for the given host.
        It will return [] if host is None (or any other falsey value).
        """
        return [v.getID() for v in host.getVulns()] if host else []

    def _is_vuln_of_host(self, vuln_id, host_id):
        """Return a boolean indicating whether vuln_id is associated with the
        host of host_id. Potentially slow, as it makes a request to the server.
        """
        host = self.get_single_host_function(host_id)
        return vuln_id in self._vulns_ids_of_host(host)

    def _add_single_host_to_model(self, host):
        """Add a single host to the model. Return None."""
        vuln_count = host.getVulnAmount()
        os_icon, os_str = self.__decide_icon(host.getOS())
        display_str = str(host)
        host_iter = self.model.append([host.id, os_icon, os_str, display_str, vuln_count])
        self.host_id_to_iter[host.id] = host_iter
        self.host_amount_in_model += 1

    def add_relevant_hosts_to_model(self, hosts):
        """Takes a list of hosts. Add the hosts to the model without going
        over the maximun size of the model. Return None.
        """
        space_left_in_sidebar = 20 - self.host_amount_in_model
        relevant_hosts = hosts[0:space_left_in_sidebar]  # just ignore those coming after
        map(self._add_single_host_to_model, relevant_hosts)

    def _update_single_host_name_in_model(self, host_id, host_iter):
        """Take a host_id and a host_iter. Changes the string representation
        of the host in the model. Potentially slow, makes a request to the server.
        Return None.

        @precondtions: host_iter must be in self.model
        """
        host = self.get_single_host_function(host_id)
        new_name = host.getName()
        vuln_amount = self._get_vuln_amount_from_model(host_iter)
        new_string = "{0} ({1})".format(new_name, vuln_amount)
        self.model.set_value(host_iter, 3, new_string)

    def update_relevant_host_names_in_model(self, hosts):
        """Takes a list of hosts and updates their string representation
        in the model. Potentially slow, makes len(hosts) requests to the server.
        Return None.
        """
        hosts_ids = map(lambda h: h.id, hosts)
        relevant_hosts = filter(self._is_host_in_model_by_host_id, hosts_ids)
        host_iters = map(lambda h: self.host_id_to_iter[h], relevant_hosts)
        map(self._update_single_host_name_in_model, relevant_hosts, host_iters)

    def _remove_single_host_from_model(self, host_id):
        """Remove the host of host_id from the model. Return None.

        @preconditions: host_id must be in self.host_id_to_iter,
                       self.host_id_to_iter[host_id] must be in model
        """
        host_iter = self.host_id_to_iter[host_id]
        del self.host_id_to_iter[host_id]
        self.model.remove(host_iter)
        self.host_amount_total -= 1
        self.host_amount_in_model -= 1

    def remove_relevant_hosts_from_model(self, host_ids):
        """Takes a list of host_ids and deletes the one found on the model
        from there. Return None."""
        relevant_host_ids = filter(self._is_host_in_model_by_host_id, host_ids)
        map(self._remove_single_host_from_model, relevant_host_ids)

    def _modify_vuln_amount_of_single_host_in_model(self, host_id, new_vuln_amount):
        """Take a host_id and a new_vuln amount and modify the string representation
        and the vuln amount of the host of id host_id in the model according
        to the new_vuln_amount. Return None.

        @preconditions: host_id must be in self.host_id_to_iter,
                        self.host_id_to_iter[host_id] must in the model.
        """
        host_iter = self.host_id_to_iter[host_id]
        current_host_name = self.model[host_iter][3].split(" ")[0]
        new_host_string = "{0} ({1})".format(current_host_name, new_vuln_amount)
        self.model.set_value(host_iter, 4, new_vuln_amount)
        self.model.set_value(host_iter, 3, new_host_string)

    def _modify_vuln_amounts_of_hosts_in_model(self, host_ids, plus_one_or_minus_one):
        """Takes host_ids (a list of host ids) and a function which should
        add or take one from an input. Modify the string representation
        and the vuln_amount of the host_ids found in the model by adding or taking
        one vulnerability from them, according to the plus_one_or_minus_one
        function. Return None.
        """
        relevant_host_ids = filter(self._is_host_in_model_by_host_id, host_ids)
        host_iters = map(lambda h: self.host_id_to_iter[h], relevant_host_ids)
        vuln_amount_of_those_hosts = map(self._get_vuln_amount_from_model, host_iters)
        new_vuln_amounts = map(plus_one_or_minus_one, vuln_amount_of_those_hosts)
        map(self._modify_vuln_amount_of_single_host_in_model, relevant_host_ids, new_vuln_amounts)

    def add_relevant_vulns_to_model(self, vulns):
        """Takes vulns, a list of vulnerability object, and adds them to the
        model by modifying their corresponding hosts in the model. Return None.
        """
        host_ids = map(self._find_host_id, vulns)
        self._modify_vuln_amounts_of_hosts_in_model(host_ids, lambda x: x+1)

    def remove_relevant_vulns_from_model(self, vuln_ids):
        """Takes vulns_ids, a list of vuln ids, and removes them from
        the model by modifying their corresponding hosts in the model.
        Return None.
        """
        host_ids = map(lambda v: v.getID().split(".")[0], vulns_ids)
        self._modify_vuln_amounts_of_hosts_in_model(host_ids, lambda x: x-1)

    def add_host(self, host):
        """Adds host to the model. Do not use for hosts added after
        the initial load of the workspace, use add_host_after_initial_load
        for that.
        """
        self.add_relevant_hosts_to_model([host])

    def remove_host(self, host_id):
        """Remove host of host_id from the model, if found in it."""
        self.remove_relevant_hosts_from_model([host_id])

    def update_host_name(self, host):
        """Update the host name of host in the model, if found in it."""
        self.update_relevant_host_names_in_model([host])

    def add_vuln(self, vuln):
        """Adds vuln to the corresponding host, if the host is found in the model."""
        self.add_relevant_vulns_to_model([vuln])

    def remove_vuln(self, vuln_id):
        """Removes a vuln from its host, if the host is found in the model."""
        self.remove_relevant_vulns_from_model([vuln_id])

    def add_host_after_initial_load(self, host):
        """Adds a host after the initial load of the sidebar.
        This implies modifiying the total host amount and potentially
        updating the progress buttons senstivity.
        """
        self.host_amount_total += 1
        self.add_host(host)
        self.set_move_buttons_sensitivity()

    def add_object(self, obj):
        """Add and object obj of unkwonw type to the model, if found there"""
        object_type = obj.class_signature
        if object_type == 'Host':
            self.add_host_after_initial_load(host=obj)
        if object_type == "Vulnerability" or object_type == "VulnerabilityWeb":
            self.add_vuln(vuln=obj)

    def remove_object(self, obj_id):
        """Remove an obj of id obj_id from the model, if found there"""
        potential_host_id = obj_id.split('.')[0]
        is_host = len(obj_id.split('.')) == 1
        if is_host:
            self.remove_host(host_id=obj_id)
        # elif not is_host and self._is_vuln_of_host(vuln_id=obj_id, host_id=potential_host_id):
        #     self.remove_vuln(vuln_id=obj_id)
        else:
            # Since we don't know the type of the delete object,
            # we have to assume it's a vulnerability so the host's
            # name is updated with the ammount of vulns
            host = self.get_single_host_function(potential_host_id)
            if host:
                self._modify_vuln_amount_of_single_host_in_model(host.getID(), host.getVulnAmount())

    def update_object(self, obj):
        """Update the obj in the model, if found there"""
        object_type = obj.class_signature
        if object_type == 'Host':
            self.update_host_name(obj)

    def on_click(self, tree_view, path, column):
        """Sends the host_id of the clicked host back to the application"""
        tree_iter = self.model.get_iter(path)
        host_id = self.model[tree_iter][0]
        self.open_dialog_callback(host_id)

    def set_move_buttons_sensitivity(self):
        """Update the sensitity of the prev and next buttons according to the
        page we're on and the total number of pages.
        """
        self.prev_button.set_sensitive(self.page > 0)  # its a boolean!

        # we add one to self.page 'cause they start at zero, but number of pages is
        # always at least one :)
        self.next_button.set_sensitive(self.number_of_pages > self.page + 1)

    def get_box(self):
        """Return the sidebar_box, which contains all the elements of the
        sidebar.
        """
        search_entry = self.create_search_entry()
        scrollable_view = self.scrollable_view()
        button_box = self.button_box()
        sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        sidebar_box.pack_start(search_entry, False, False, 0)
        sidebar_box.pack_start(scrollable_view, True, True, 0)
        sidebar_box.pack_start(button_box, False, True, 0)
        return sidebar_box

    def button_box(self):
        """Return the button_box, which contains the prev and next button
        as well the progress label. Creates the instance attributes
        self.prev_button and self.next_button.
        """
        button_box = Gtk.Box()
        button_box.override_background_color(Gtk.StateType.NORMAL, Gdk.RGBA(.1, .1, .1, .1))
        self.prev_button = Gtk.Button.new_with_label("<<")
        self.next_button = Gtk.Button.new_with_label(">>")
        self.prev_button.connect("clicked", self.on_click_move_page, lambda x: x-1)
        self.next_button.connect("clicked", self.on_click_move_page, lambda x: x+1)
        button_box.pack_start(self.prev_button, True, True, 0)
        button_box.pack_start(self.progress_label, True, True, 0)
        button_box.pack_start(self.next_button, True, True, 0)
        return button_box

    def on_click_move_page(self, button, change_page_number_func, *args, **kwargs):
        """What happens when the user clicks on either self.prev_button
        or self.next_button. Change self.page according to the change_page_number_func,
        and resets the model to a new list of hosts requested from the server.
        """
        self.page = change_page_number_func(self.page)
        hosts = self.get_hosts_function(page=str(self.page),
                                        page_size=20,
                                        name=self.search_entry.get_text(),
                                        sort='vulns',
                                        sort_dir='desc')
        self.reset_model(hosts)
        self.update_progress_label()

    def update_progress_label(self):
        """Updates the progress label with values from self.page and self.number_of_pages."""
        self.progress_label.set_label("{0} / {1}".format(self.page+1, self.number_of_pages))

    def create_search_entry(self):
        """Returns a simple search entry"""
        self.search_entry = Gtk.Entry()
        self.search_entry.set_placeholder_text("Search a host by name...")
        self.search_entry.connect("activate", self.on_search_enter_key)
        self.search_entry.show()
        return self.search_entry

    def on_search_enter_key(self, entry):
        """Rebuild the model with the search, but self.page stays the same.
        """
        self.on_click_move_page(Gtk.Button(), lambda i: i)


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

        for ws in added_workspaces:
            if ws not in self.workspaces:
                iter = self.get_iter_by_name(ws)
                self.workspace_model.remove(iter)

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
        return True  # prevents the click from selecting a workspace
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
        # NOTE. this function should really be replaced by a dictionary
        for ws_iter in self.valid_ws_iters:
            if self.workspace_model.iter_is_valid(ws_iter):
                if self.workspace_model[ws_iter][0] == ws_name:
                    return ws_iter
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

    def news_button(self, url, description):

            anchor = self.textBuffer.create_child_anchor(
                self.textBuffer.get_end_iter())

            button = Gtk.Button()
            label = Gtk.Label()

            label.set_markup(
                'Faraday News: <a href="' + url + '"> ' +
                description + "</a>")

            button.add(label)
            button.set_relief(Gtk.ReliefStyle.NONE)

            button.connect("clicked", lambda o: webbrowser.open())

            label.show()
            button.show()
            self.update("\n")

            self.textView.add_child_at_anchor(button, anchor)

    def customEvent(self, text):
        """Filters event so that only those with type 3131 get to the log.
        Also split them, so we can add the correct formatting to the first
        part of the message"""

        text = text.split('-', 1)
        if text[0] == "INFO ":
            self.update("[ " + text[0] + "]", self.bold)
        elif text[0] == "DEBUG ":
            self.update("[ " + text[0] + "]", self.bold, self.green)
        elif text[0] == "ERROR " or text[0] == "CRITICAL: ":
            self.update("[ " + text[0] + "]", self.bold, self.red)
        elif text[0] == "WARNING ":
            self.update("[ " + text[0] + "]", self.bold, self.orange)
        elif text[0] == "NOTIFICATION ":
            self.update("[ " + text[0] + "]", self.bold, self.blue)
        elif text[0] == "NEWS ":
            # Format of data : 'NEWS - URL|DESC'
            data_url_desc = text[1].split('|')
            self.news_button(data_url_desc[0], data_url_desc[1])
            return

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
