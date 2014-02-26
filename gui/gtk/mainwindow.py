#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os

from gi.repository import Gtk, GdkPixbuf

from gui.gtk.tabmanager import TabManager

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, app):
        Gtk.Window.__init__(self, title="Faraday IPE", application=app)
        self.maximize()

        grid = Gtk.Grid()
        self.add(grid)

        self.setup_icons()
        menubar, toolbar = self.setup_menus()
        grid.attach(menubar, 0, 0, 2, 1)
        grid.attach_next_to(toolbar, menubar, Gtk.PositionType.BOTTOM, 2, 1)
        self.tab_manager = self.setup_tab_manager()
        grid.attach_next_to(self.tab_manager, toolbar,
                            Gtk.PositionType.BOTTOM, 1, 1)
        self.setup_hosttree_view()
        self.setup_log_console()
        self.setup_status_bar()

        self.show_all()

    def setup_menus(self):
        UI_INFO = """
            <ui>
              <menubar name='MenuBar'>
                <menu action='FileMenu'>
                  <menuitem action='FileQuit' />
                </menu>
                <menu action='ShellMenu'>
                  <menuitem action='ShellNew' />
                  <menuitem action='ShellClose' />
                  <menuitem action='ShellSizeFontIncrease' />
                  <menuitem action='ShellSizeFontIncrease' />
                </menu>
                <menu action='EditMenu'>
                  <menuitem action='EditCopy' />
                  <menuitem action='EditPaste' />
                  <menuitem action='EditServerConnection' />
                </menu>
                <menu action='WorkspaceMenu'>
                  <menuitem action='WorskpaceCreate' />
                </menu>
                <menu action='ToolsMenu'>
                  <menuitem action='ToolsScreenshot' />
                  <menuitem action='ToolsPlugins' />
                  <menuitem action='ToolsVisualization' />
                  <menuitem action='ToolsReconnect' />
                </menu>
                <menu action='ViewMenu'>
                  <menuitem action='ViewToggleHostTree' />
                  <menuitem action='ViewToggleLogConsole' />
                  <menuitem action='ViewMaximizeShell' />
                </menu>
                <menu action='HelpMenu'>
                  <menuitem action='HelpAbout'/>
                  <menuitem action='HelpDocumentation'/>
                </menu>
              </menubar>
              <toolbar name='ToolBar'>
                <toolitem action='ShellNew' />
                <toolitem action='ViewToggleHostTree' />
                <toolitem action='ViewToggleLogConsole' />
                <toolitem action='ViewMaximizeShell' />
                <toolitem action='EditServerConnection' />
                <toolitem action='ToolsVisualization' />
                <toolitem action='ToolsPlugins' />
                <toolitem action='ToolsScreenshot' />
                <toolitem action='ToolsReconnect' />
                <toolitem action='ShellSizeFontIncrease' />
                <toolitem action='ShellSizeFontDecrease' />
              </toolbar>
            </ui>
            """

        action_group = Gtk.ActionGroup("actions")

        self.add_file_menu_actions(action_group)
        self.add_shell_menu_actions(action_group)
        self.add_edit_menu_actions(action_group)
        self.add_workspace_menu_actions(action_group)
        self.add_tools_menu_actions(action_group)
        self.add_view_menu_actions(action_group)
        self.add_help_menu_actions(action_group)

        uimanager = self.create_ui_manager(UI_INFO)
        uimanager.insert_action_group(action_group)

        menubar = uimanager.get_widget("/MenuBar")

        #box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        #box.pack_start(menubar, False, False, 0)

        toolbar = uimanager.get_widget("/ToolBar")
        #box.pack_start(toolbar, False, False, 0)

        # self.add(box)
        return (menubar, toolbar)

    def add_file_menu_actions(self, action_group):
        action_file_menu = Gtk.Action("FileMenu", "File", None, None)
        action_group.add_action(action_file_menu)

        action_file_quit = Gtk.Action("FileQuit", "_Quit", None, Gtk.STOCK_QUIT)
        action_file_quit.connect("activate", self.on_menu_file_quit)
        action_group.add_action_with_accel(action_file_quit, None)

    def add_shell_menu_actions(self, action_group):
        action_group.add_actions([
            ("ShellMenu", None, "Shell"),
            ("ShellNew", "newshell", "New", None, "New Shell", self.on_menu_shell_new),
            ("ShellClose", "exit", "Close", None, None, None),
            ("ShellSizeFontIncrease", "fontb", "Increase font size", None, "Increase font size", None),
            ("ShellSizeFontDecrease", "fonts", "Decrease font size", None, "Decrease font size", None)
        ])

    def add_edit_menu_actions(self, action_group):
        action_group.add_actions([
            ("EditMenu", None, "Edit"),
            ("EditCopy", Gtk.STOCK_COPY, None, None, None, None),
            ("EditPaste", Gtk.STOCK_PASTE, None, None, None, None),
            ("EditServerConnection", "connect", "Server connection", None, "Server connection", None)
        ])

    def add_workspace_menu_actions(self, action_group):
        action_group.add_actions([
            ("WorkspaceMenu", None, "Workspace"),
            ("WorskpaceCreate", "sync", "Create", None, None, None)
        ])

    def add_tools_menu_actions(self, action_group):
        action_group.add_actions([
            ("ToolsMenu", None, "Tools"),
            ("ToolsVisualization", "visualize", "Visualize", None, "Visualize", None),
            ("ToolsPlugins", "config", "Plugins settings", None, None, None),
            ("ToolsScreenshot", "screenshot", "Take screenshot", None, "Take screenshot", None),
            ("ToolsReconnect", "sync", "Reconnect", None, "Reconnect", None)
        ])

    def add_view_menu_actions(self, action_group):
        action_group.add_actions([
            ("ViewMenu", None, "View"),
            ("ViewMaximizeShell", "maximize", "Maximize Shell", None, "Maximize Shell", None)
        ])
        action_group.add_toggle_actions([
            ("ViewToggleHostTree", "hosttreeview", "Toggle HostTree", None, None, None),
            ("ViewToggleLogConsole", "logconsole", "Toggle Log Console", None, None, None),
        ])

    def add_help_menu_actions(self, action_group):
        action_group.add_actions([
            ("HelpMenu", None, "Help"),
            ("HelpAbout", Gtk.STOCK_ABOUT, "About", None, None, None),
            ("HelpDocumentation", "documentation", "Documentation", None, None, None)
        ])

    def create_ui_manager(self, ui_info):
        uimanager = Gtk.UIManager()

        uimanager.add_ui_from_string(ui_info)

        accelgroup = uimanager.get_accel_group()
        self.add_accel_group(accelgroup)
        return uimanager

    def setup_icons(self):
        self.set_icon_from_file(
            os.path.join(CONF.getIconsPath(), "faraday_icon.png"))

        icons = [f for f in os.listdir(CONF.getIconsPath())
                 if os.path.isfile(os.path.join(CONF.getIconsPath(), f))]

        icon_factory = Gtk.IconFactory()

        for icon in icons:
            icon_set = Gtk.IconSet.new_from_pixbuf(
                GdkPixbuf.Pixbuf.new_from_file(os.path.join(
                    CONF.getIconsPath(), icon)))

            icon_factory.add(icon.lower().split('.')[0], icon_set)

        icon_factory.add_default()

    def setup_tab_manager(self):
        return TabManager()

    def setup_hosttree_view(self):
        pass

    def setup_log_console(self):
        pass

    def setup_status_bar(self):
        pass

    def on_menu_file_quit(self, widget):
        self.close()

    def on_menu_shell_new(self, widget):
        self.tab_manager.create_new_shell()
