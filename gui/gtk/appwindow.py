# -*- coding: utf-8 -*-
import gi
from mainwidgets import Terminal

from config.configuration import getInstanceConfiguration

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import GLib, Gio, Gtk, GObject, Gdk

CONF = getInstanceConfiguration()


class _IdleObject(GObject.GObject):
    """
    Override GObject.GObject to always emit signals in the main thread
    by emmitting on an idle handler
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
        "clear_notifications" : (GObject.SIGNAL_RUN_FIRST, None, ())
    }

    def __init__(self, sidebar, terminal, console_log, statusbar,
                 *args, **kwargs):
        super(Gtk.ApplicationWindow, self).__init__(*args, **kwargs)

        # This will be in the windows group and have the "win" prefix
        glib_variant = GLib.Variant.new_boolean(False)
        max_action = Gio.SimpleAction.new_stateful("maximize", None,
                                                   glib_variant)
        max_action.connect("change-state", self.on_maximize_toggle)
        self.add_action(max_action)

        self.sidebar = sidebar
        self.terminal = terminal
        self.log = console_log
        self.statusbar = statusbar

        #sets up the clipboard
        self.clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        self.selection_clipboard = Gtk.Clipboard.get(Gdk.SELECTION_PRIMARY)

        # Keep it in sync with the actual state. Deep dark GTK magic
        self.connect("notify::is-maximized",
                     lambda obj:
                     max_action.set_state(
                         GLib.Variant.new_boolean(obj.props.is_maximized)))

        #TOP BOX: TOOLBAR AND FILTER
        self.topBox = Gtk.Box()
        self.topBox.pack_start(self.create_toolbar(), True, True, 0)

        #SIDEBAR BOX
        self.sidebarBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.sidebarBox.pack_start(self.sidebar.scrollableView, True, True, 0)
        self.sidebarBox.pack_start(self.sidebar.sidebar_button, False, False, 0)

        #TERMINAL BOX
        self.firstTerminalBox = self.terminalBox(self.terminal.getTerminal())

        # MIDDLE BOX: NOTEBOOK AND SIDEBAR
        self.notebook = Gtk.Notebook()
        self.notebook.set_scrollable(True)
        self.notebook.append_page(self.firstTerminalBox, Gtk.Label("1"))

        self.middleBox = Gtk.Box()
        self.middleBox.pack_start(self.notebook, True, True, 0)
        self.middleBox.pack_start(self.sidebarBox, False, False, 0)

        # LOGGER BOX: THE LOGGER, DUH
        self.loggerBox = Gtk.Box()
        self.loggerBox.pack_start(self.log.getLogger(), True, True, 0)

        # NOTIFACTION BOX: THE BUTTON TO ACCESS NOTIFICATION DIALOG
        self.notificationBox = Gtk.Box()
        self.notificationBox.pack_start(self.statusbar.button, True, True, 0)

        # MAINBOX: THE BIGGER BOX OF ALL THE LITTLE BOXES
        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.mainBox.pack_start(self.topBox, False, False, 0)
        self.mainBox.pack_start(self.middleBox, True, True, 0)
        self.mainBox.pack_start(self.loggerBox, False, False, 0)
        self.mainBox.pack_end(self.notificationBox, False, False, 0)

        self.add(self.mainBox)
        self.tab_number = 0  # 0 indexed

        self.show_all()

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
        copy = Gtk.MenuItem("Copy")
        paste = Gtk.MenuItem("Paste")
        menu.append(paste)
        menu.append(copy)

        accelgroup = Gtk.AccelGroup()
        self.add_accel_group(accelgroup)
        accellabel = Gtk.AccelLabel("Ctrl+Shift+C")
        accellabel.set_hexpand(True)
        copy.add_accelerator("activate",
                             accelgroup,
                             Gdk.keyval_from_name("C"),
                             Gdk.ModifierType.CONTROL_MASK,
                             Gtk.AccelFlags.VISIBLE)

        copy.connect("activate", self.copy_text)
        paste.connect("activate", self.paste_text)

        copy.show()
        paste.show()
        menu.popup(None, None, None, None, event.button, event.time)

    def copy_text(self, button):
        """What happens when the user copies text"""
        content = self.selection_clipboard.wait_for_text()
        self.clipboard.set_text(content, -1)

    def paste_text(self, button):
        """What happens when the user pastes text"""
        currentTab = self.notebook.get_current_page()
        currentTerminal = self.getCurrentFocusedTerminal()
        currentTerminal.paste_clipboard()

    def getFocusedTab(self):
        """Return the focused tab"""
        return self.notebook.get_current_page()

    def getCurrentFocusedTerminal(self):
        """The focused terminal is the only children of the notebook
        which has as only children an eventbox which has as only
        children the terminal"""
        currentTab = self.getFocusedTab()
        currentEventBox = self.notebook.get_children()[currentTab]
        currentBox = currentEventBox.get_children()[0]
        currentTerminal = currentBox.get_children()[0]
        return currentTerminal

    def do_new_log(self, text):
        """What should the window do when it gets a new_log signal"""
        self.log.customEvent(text)

    def do_clear_notifications(self):
        self.statusbar.button.set_label("0")

    def do_new_notif(self):
        self.statusbar.inc_button_label()

    def getLogConsole(self):
        """Returns the LogConsole. Needed by the GUIHandler logger"""
        # This explodes everywhere, it is very weird. Pass works for now
        return self.log

    def on_maximize_toggle(self, action, value):
        """Defines what happens when the window gets the signal to maximize"""
        action.set_state(value)
        if value.get_boolean():
            self.maximize()
        else:
            self.unmaximize()

    def refreshSidebar(self):
        self.sidebar.refresh()

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

        new_terminal_button = Gtk.ToolButton.new_from_stock(Gtk.STOCK_DND)
        new_terminal_button.set_is_important(True)
        new_terminal_button.set_action_name('app.new_terminal')
        toolbar.insert(new_terminal_button, 1)

        remove_terminal_button = Gtk.ToolButton.new_from_stock(Gtk.STOCK_REMOVE)
        remove_terminal_button.set_is_important(True)
        remove_terminal_button.connect("clicked", self.delete_tab)
        toolbar.insert(remove_terminal_button, 2)

        return toolbar

    def new_tab(self, new_terminal):
        """The on_new_terminal_button redirects here. Tells the window
        to create pretty much a clone of itself when the user wants a new
        tab"""

        self.tab_number += 1
        tab_number = self.tab_number
        pageN = self.terminalBox(new_terminal)
        self.notebook.append_page(pageN, Gtk.Label(str(tab_number+1)))
        self.show_all()

    def delete_tab(self, button):
        """Deletes the current tab"""
        current_page = self.notebook.get_current_page()
        self.notebook.remove_page(current_page)
        self.reorder_tab_names()

    def reorder_tab_names(self):
        """When a tab is deleted, all other tabs must be renamed to reacomodate
        the numbers"""
        #Tabs are zero indexed, but their labels start at one

        number_of_tabs = self.notebook.get_n_pages()
        for n in range(number_of_tabs):
            tab = self.notebook.get_nth_page(n)
            self.notebook.set_tab_label_text(tab, str(n+1))
        self.tab_number = number_of_tabs-1
