# -*- coding: utf-8 -*-
import os
import sys
import gi

from config.configuration import getInstanceConfiguration
from consolelog import ConsoleLog
from mainwidgets import Sidebar

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import GLib, Gio, Gtk, Vte, GObject, Gdk


CONF = getInstanceConfiguration()


class AppWindow(Gtk.ApplicationWindow):
    """The main window of the GUI. Draws toolbar, terminal and sidebar.
    It also receives the new_log signal from the main app, which is used
    to display log information on the text box defined in ConsoleLog module"""

    __gsignals__ = {
                "new_log": (GObject.SIGNAL_RUN_FIRST, None, (str, int, )),
                "new_notif": (GObject.SIGNAL_RUN_FIRST, None, (str, ))
                }

    def __init__(self, workspace_manager, *args, **kwargs):
        super(Gtk.ApplicationWindow, self).__init__(*args, **kwargs)

        # This will be in the windows group and have the "win" prefix
        glib_variant = GLib.Variant.new_boolean(False)
        max_action = Gio.SimpleAction.new_stateful("maximize", None,
                                                   glib_variant)
        max_action.connect("change-state", self.on_maximize_toggle)
        self.add_action(max_action)

        self.workspace_manager = workspace_manager
        # creates an instance of ConsoleLog and puts it in a box
        self.log = ConsoleLog()
        self.loggerBox = Gtk.Box()
        self.loggerBox.pack_start(self.log.getView(), True, True, 0)

        # creates an instance of statusbar and puts it in a box
        self.statusbar = Gtk.Statusbar.new()
        self.statusbarBox = Gtk.Box()
        self.statusbarBox.pack_start(self.statusbar, True, True, 0)

        # Keep it in sync with the actual state. Deep dark GTK magic
        self.connect("notify::is-maximized",
                     lambda obj:
                     max_action.set_state(
                         GLib.Variant.new_boolean(obj.props.is_maximized)))

        # the main layout of our window is a notebook which supports tabs
        self.notebook = Gtk.Notebook()
        self.notebook.popup_enable()

        # TODO: override_background_color is deprecated. prolly best
        # to use something else. this works for now so as to make
        # the notebooks background not white
        self.notebook.override_background_color(0, Gdk.RGBA(0, 0, 0, 0))

        self.add(self.notebook)
        self.page1 = self.mainBox_creator()
        self.notebook.append_page(self.page1, Gtk.Label("1"))
        self.tab_number = 0  # 0 indexed

        self.show_all()

    def do_new_log(self, text, type_):
        """What should the window do when it gets a new_log signal"""
        self.log.customEvent(text, type_)

    def getLogConsole(self):
        """Returns the LogConsole. Needed by the GUIHandler logger"""
        # This explodes everywhere, it is very weird. Pass works for now
        pass

    def mainBox_creator(self):
        """Creates the mainbox of the Window, where all the other small
        little boxes live"""

        mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        toolbarBox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        middleBox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        terminalBox = Gtk.Box()
        sidebarBox = Gtk.Box()

        toolbar = self.create_toolbar()
        terminal = self.create_terminal()

        sidebar = Sidebar(self.workspace_manager).getWSList()

        filtr = self.create_filter()  # weird name 'cause filter is reserved

        sidebarBox.pack_start(sidebar , False, True, 0)
        terminalBox.pack_start(terminal, True, True, 0)

        middleBox.pack_start(terminalBox, True, True, 0)
        middleBox.pack_end(sidebarBox, False, False, 0)

        toolbarBox.pack_start(toolbar, True, True, 0)
        toolbarBox.pack_end(filtr, False, False, 0)

        mainBox.pack_start(toolbarBox, False, False, 0)
        mainBox.pack_start(middleBox, True, True, 0)
        mainBox.pack_start(self.loggerBox, False, False, 0)
        mainBox.pack_start(self.statusbarBox, False, False, 0)

        return mainBox

    def create_terminal(self):
        """ Creates a Vte terminal that executes zsh and opens Farday
        with the host and port specified in the user's config
        """

        terminal = Vte.Terminal()
        faraday_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
        terminal.spawn_sync(Vte.PtyFlags.DEFAULT,
                            faraday_directory, ['/bin/zsh'],
                            [],
                            GLib.SpawnFlags.DO_NOT_REAP_CHILD,
                            None,
                            None)

        host, port = CONF.getApiRestfulConInfo()

        faraday_exec = './faraday-terminal.zsh'
        self.command = (faraday_exec + " " + host + " " + str(port))
        terminal.feed_child(self.command + '\n', len(self.command)+1)
        return terminal

    def on_maximize_toggle(self, action, value):
        """Defines what happens when the window gets the signal to maximize"""
        action.set_state(value)
        if value.get_boolean():
            self.maximize()
        else:
            self.unmaximize()

    def create_filter(self):

        entryBox = Gtk.Box()
        entry = Gtk.Entry()
        entry.set_text("Filter")
        entryBox.pack_start(entry, True, True, 0)

        return entryBox

    def create_toolbar(self):
        """ Creates toolbar with an open and new button, getting the icons
        from the stock. The method by which it does this is deprecated,
        this could be improved"""

        toolbar = Gtk.Toolbar()
        toolbar.set_hexpand(True)
        toolbar.get_style_context().add_class(Gtk.STYLE_CLASS_PRIMARY_TOOLBAR)

        # new_from_stock is deprecated, but should work fine for now
        new_button = Gtk.ToolButton.new_from_stock(Gtk.STOCK_NEW)
        new_button.set_is_important(True)
        toolbar.insert(new_button, 0)
        new_button.set_action_name('app.new')

        open_button = Gtk.ToolButton.new_from_stock(Gtk.STOCK_OPEN)
        open_button.set_is_important(True)
        toolbar.insert(open_button, 1)
        open_button.set_action_name('app.open')

        new_terminal_button = Gtk.ToolButton.new_from_stock(Gtk.STOCK_DND)
        new_terminal_button.set_is_important(True)
        new_terminal_button.set_action_name('app.new_terminal')
        toolbar.insert(new_terminal_button, 2)

        return toolbar

    def new_tab(self):
        """The on_new_terminal_button redirects here. Tells the window
        to create pretty much a clone of itself when the user wants a new
        tab"""

        self.tab_number += 1
        tab_number = self.tab_number
        pageN = self.mainBox_creator()
        self.notebook.append_page(pageN, Gtk.Label(str(tab_number+1)))
        self.show_all()
