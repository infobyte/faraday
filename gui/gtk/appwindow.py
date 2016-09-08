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

from gi.repository import GLib, Gio, Gtk, GObject, Gdk
from dialogs import ImportantErrorDialog

CONF = getInstanceConfiguration()


class AppWindow(Gtk.ApplicationWindow):
    """The main window of the GUI. Draws the toolbar.
    Positions the terminal, sidebar, consolelog and statusbar received from
    the app and defined in the mainwidgets module"""

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
        # Keep it in sync with the actual state. Deep dark GTK magic
        self.connect("notify::is-maximized",
                     lambda obj, pspec:
                     max_action.set_state(
                         GLib.Variant.new_boolean(obj.props.is_maximized)))

        self.tab_number = 0  # 0 indexed, even when it shows 1 to the user
        self.sidebar = sidebar
        self.ws_sidebar = ws_sidebar
        self.hosts_sidebar = hosts_sidebar
        self.terminal = terminal
        self.log = console_log
        self.statusbar = statusbar

        self.terminal.connect("child_exited", self.on_terminal_exit)
        self.icons = CONF.getImagePath() + "icons/"

        window = self.create_window_main_structure()
        self.add(window)

        self.append_remove_terminal_button_to_notebook()
        self.show_all()

    def create_window_main_structure(self):
        """Return a box with the main structure of the window. Looks like this:
        |-------------------------|
        |     TOOLBAR             |
        |-------------------------|
        |     TERMINAL     | SIDE |
        |                  | BAR  |
        |-------------------------|
        |         LOG BOX         |
        |        STATUSBAR        |
        |-------------------------|
        """
        scrollable_terminal = self.terminal.create_scrollable_terminal()
        terminal_event_box = self.create_event_box(scrollable_terminal)

        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self.notebook.append_page(terminal_event_box, Gtk.Label("1"))

        middle_pane = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL)
        middle_pane.pack1(self.notebook, True, False)
        middle_pane.pack2(self.sidebar.box_it(), False, False)

        self.log_box = self.log.create_scrollable_logger()

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.pack_start(self.create_toolbar(), False, False, 0)
        main_box.pack_start(middle_pane, True, True, 0)
        main_box.pack_start(self.log_box, False, False, 0)
        main_box.pack_start(self.statusbar.mainBox, False, False, 0)
        return main_box

    def append_remove_terminal_button_to_notebook(self):
        """Apprends a remove_terminal_icon to the end of notebooks
        action area"""
        remove_terminal_icon = Gtk.Image.new_from_file(self.icons + "exit.png")
        remove_terminal_button = Gtk.Button()
        remove_terminal_button.set_tooltip_text("Delete current tab")
        remove_terminal_button.connect("clicked", self.delete_tab)
        remove_terminal_button.set_image(remove_terminal_icon)
        remove_terminal_button.set_relief(Gtk.ReliefStyle.NONE)
        remove_terminal_button.show()
        self.notebook.set_action_widget(remove_terminal_button, Gtk.PackType.END)

    def receive_hosts(self, hosts):
        """Attaches the hosts to an object value, so it can be used by
        do_update_hosts_sidebar, a signal. GTK won't alow anything
        more than primitive names to be passed on by signals"""
        self.current_hosts = hosts

    def create_event_box(self, widget):
        """Given a terminal, creates an EventBox for the Box that has as a
        children said terminal"""
        event_box = Gtk.EventBox()
        event_box.connect("button_press_event", self.right_click)
        event_box.add(widget)
        return event_box

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
        currentTerminal = self.get_current_focused_terminal()
        currentTerminal.copy_clipboard()

    def paste_text(self, _):
        """When the user presses on the paste button on the menu..."""
        currentTerminal = self.get_current_focused_terminal()
        currentTerminal.paste_clipboard()

    def get_current_focused_terminal(self):
        """Returns the current focused terminal"""

        # the focused terminal is the child of the event box which is
        # the top widget of the focused tab. that event box has as only child
        # only child a scrolled window, which has as only child the terminal.
        # Yeah. I know.

        current_tab = self.notebook.get_current_page()
        current_event_box = self.notebook.get_children()[current_tab]
        current_scrolled_window = current_event_box.get_children()[0]
        current_terminal = current_scrolled_window.get_child()
        return current_terminal

    def destroy_from_button(self, button=None):
        """Sometimes this stuff is needed, 'cause it needs to take a button
        as parameter. See do_delete_event() for explanation on why the
        _not_ is there.
        """
        if not self.do_delete_event():
            self.destroy()

    def on_maximize_toggle(self, action, value):
        """Defines what happens when the window gets the signal to maximize"""
        action.set_state(value)
        if value.get_boolean():
            self.maximize()
        else:
            self.unmaximize()

    def create_toolbar(self):
        """Creates the toolbar for the window."""

        toolbar = Gtk.Toolbar()
        toolbar.set_hexpand(True)
        icons = self.icons

        new_button_icon = Gtk.Image.new_from_file(icons + "Documentation.png")
        new_terminal_icon = Gtk.Image.new_from_file(icons + "newshell.png")
        preferences_icon = Gtk.Image.new_from_file(icons + "config.png")
        toggle_log_icon = Gtk.Image.new_from_file(icons + "debug.png")
        open_report_icon = Gtk.Image.new_from_file(icons + "FolderSteel-20.png")
        go_to_web_ui_icon = Gtk.Image.new_from_file(icons + "visualize.png")

        new_terminal_button = Gtk.ToolButton.new(new_terminal_icon, None)
        new_terminal_button.set_tooltip_text("Create a new tab")
        new_terminal_button.set_label("New tab")
        new_terminal_button.set_action_name('app.new_terminal')
        toolbar.insert(new_terminal_button, 0)

        new_button = Gtk.ToolButton.new(new_button_icon, None)
        new_button.set_tooltip_text("Create a new workspace")
        new_button.set_label("New Workspace")
        toolbar.insert(new_button, 1)
        new_button.set_action_name('app.new')

        preferences_button = Gtk.ToolButton.new(preferences_icon, None)
        preferences_button.set_tooltip_text("Preferences")
        preferences_button.set_label("Preferences")
        toolbar.insert(preferences_button, 2)
        preferences_button.set_action_name('app.preferences')

        toggle_log_button = Gtk.ToggleToolButton.new()
        toggle_log_button.set_icon_widget(toggle_log_icon)
        toggle_log_button.set_active(True)  # log enabled by default
        toggle_log_button.set_tooltip_text("Toggle log console")
        toggle_log_button.set_label("Toggle log")
        toggle_log_button.connect("clicked", self.toggle_log)
        toolbar.insert(toggle_log_button, 3)

        go_to_web_ui_button = Gtk.ToolButton.new(go_to_web_ui_icon, None)
        go_to_web_ui_button.set_tooltip_text("Go to Faraday Web")
        go_to_web_ui_button.set_label("Faraday Web")
        go_to_web_ui_button.set_action_name("app.go_to_web_ui")
        toolbar.insert(go_to_web_ui_button, 4)

        space = Gtk.ToolItem()
        space.set_expand(True)
        toolbar.insert(space, 5)

        open_report_button = Gtk.ToolButton.new(open_report_icon, None)
        open_report_button.set_label("Import report")
        open_report_button.set_tooltip_text("Import report")
        open_report_button.set_action_name('app.open_report')
        toolbar.insert(open_report_button, 6)

        return toolbar

    def new_tab(self, scrolled_window):
        """The on_new_terminal_button redirects here from the application.
        The scrolled_window will be a scrolled window containing only a VTE
        terminal.
        """

        terminal = scrolled_window.get_children()[0]
        terminal.connect("child_exited", self.on_terminal_exit)
        self.tab_number += 1
        pageN = self.create_event_box(scrolled_window)
        self.notebook.append_page(pageN, Gtk.Label(str(self.tab_number+1)))
        self.notebook.show_all()

    def delete_tab(self, button=None, tab_number=None):
        """Deletes the tab number tab_number, by default the current,
        or closes the window if tab is only tab"""
        if self.tab_number == 0:
            # the following is confusing but its how gtks handles delete_event
            # if user said YES to confirmation, do_delete_event returns False
            if not self.do_delete_event():
                self.destroy()

        else:
            if tab_number is None:
                page = self.notebook.get_current_page()
            else:
                page = self.notebook.get_nth_page(tab_number)

            self.notebook.remove_page(page)
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
        """Reverses the visibility status of the log_box"""
        current_state = self.log_box.is_visible()
        self.log_box.set_visible(not current_state)

    def show_conflicts_warning(self):
        warning_string = ("There are conflicts that need manual "
                         "handling. Closing Faraday or changing workspaces "
                         "may result in the loss of relevant information. "
                         "Are you sure you want to continue?")
        dialog = Gtk.MessageDialog(self, 0,
                                   Gtk.MessageType.QUESTION,
                                   Gtk.ButtonsType.YES_NO,
                                   warning_string)
        response = dialog.run()
        dialog.destroy()
        return response

    def do_delete_event(self, event=None, status=None, parent=None):
        """Override delete_event signal to show a confirmation dialog first.
        """
        if parent is None:
            parent = self

        # NOTE: Return False for 'yes' is weird but that's how gtk likes it
        #       Don't judge, man. Don't judge.
        if self.statusbar.conflict_button_label_int > 0:
            response = self.show_conflicts_warning()
            if response == Gtk.ResponseType.NO:
                return True
            else:
                return False

        dialog = Gtk.MessageDialog(transient_for=parent,
                                   modal=True,
                                   buttons=Gtk.ButtonsType.YES_NO)
        dialog.set_keep_above(True)
        dialog.set_modal(True)
        dialog.props.text = "Are you sure you want to quit Faraday?"
        response = dialog.run()
        dialog.destroy()

        if response == Gtk.ResponseType.YES:
            return False  # keep on going and destroy
        else:
            # user said "you know what i don't want to exit"
            return True

    def on_terminal_exit(self, terminal=None, status=None):
        """Really, it is *very* similar to delete_tab, but in this case
        we want to make sure that we restart Faraday if the user
        is not sure if he wants to exit"""
        self.delete_tab()
        terminal.start_faraday()
