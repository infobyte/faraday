import gi
import os
import sys

gi.require_version('Gtk', '3.0')
gi.require_version('Vte', '2.91')

from gi.repository import Gtk, Vte, GLib


class Terminal(Gtk.Widget):
    """Defines a simple terminal that will execute faraday-terminal with the
    corresponding host and port as specified by the CONF"""
    def __init__(self, CONF):
        super(Gtk.Widget, self).__init__()

        self.terminal = Vte.Terminal()
        faraday_directory = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.terminal.spawn_sync(Vte.PtyFlags.DEFAULT,
                                 faraday_directory, ['/bin/zsh'],
                                 [],
                                 GLib.SpawnFlags.DO_NOT_REAP_CHILD,
                                 None,
                                 None)

        host, port = CONF.getApiRestfulConInfo()
        faraday_exec = './faraday-terminal.zsh'
        self.command = (faraday_exec + " " + host + " " + str(port))
        self.terminal.feed_child(self.command + '\n', len(self.command)+1)

    def getTerminal(self):
        return self.terminal


class Sidebar(Gtk.Widget):
    """Defines the sidebar widget to be used by the AppWindow, passed as an
    instance by the application. It only handles the view, all the backend
    word is handled by the application via the callback"""

    def __init__(self, workspace_manager, callback_to_change_workspace,
                 callback_to_remove_workspace, conf):
        super(Gtk.Widget, self).__init__()
        self.callback = callback_to_change_workspace
        self.removeWsCallback = callback_to_remove_workspace
        self.ws_manager = workspace_manager
        self.lastWorkspace = conf
        self.workspaces = self.ws_manager.getWorkspacesNames()
        self.workspace_list_info = Gtk.ListStore(str)

        self.workspaceModel()
        self.workspaceView()

        self.sidebar_button = Gtk.Button.new_with_label("Refresh")
        self.sidebar_button.connect("clicked", self.refreshSidebar)

        self.scrollableView = Gtk.ScrolledWindow.new(None, None)
        self.scrollableView.set_min_content_width(160)
        self.scrollableView.add(self.lst)

    def refreshSidebar(self, button=None):
        """Function called when the user press the refresh button.
        Gets an updated copy of the workspaces and checks against
        the model to see which are already there and which arent"""
        model = self.workspace_list_info
        self.workspaces = self.ws_manager.getWorkspacesNames()
        added_workspaces = [added_ws[0] for added_ws in model]
        for ws in self.workspaces:
            if ws not in added_workspaces:
                self.addWorkspace(ws)

    def clearSidebar(self):
        self.workspace_list_info.clear()

    def createTitle(self):
        title = Gtk.Label()
        title.set_text("Workspaces")
        return title

    def workspaceModel(self):
        for ws in self.workspaces:
            treeIter = self.workspace_list_info.append([ws])
            if ws == self.lastWorkspace:
                self.defaultSelection = treeIter

    def workspaceView(self):
        self.lst = Gtk.TreeView(self.workspace_list_info)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Workspaces", renderer, text=0)
        self.lst.append_column(column)

        # select by default the last active workspace
        if self.defaultSelection is not None:
            self.selectDefault = self.lst.get_selection()
            self.selectDefault.select_iter(self.defaultSelection)

        self.lst.connect("button-press-event", self.on_right_click)
        selection = self.lst.get_selection()
        selection.connect("changed", self.callback)

    def on_right_click(self, view, event):

        if event.button == 3:
            menu = Gtk.Menu()
            delete_item = Gtk.MenuItem("Delete")
            menu.append(delete_item)

            path, _, _, _ = view.get_path_at_pos(int(event.x), int(event.y))
            tree_iter = self.workspace_list_info.get_iter(path)
            ws_name = self.workspace_list_info[tree_iter][0]

            delete_item.connect("activate", self.removeWsCallback, ws_name)

            delete_item.show()
            menu.popup(None, None, None, None, event.button, event.time)
            return True

    def addWorkspace(self, ws):
        self.workspace_list_info.append([ws])

    def getSelectedWs(self):
        return self.lst.get_selection()

    def selectWs(self, ws):
        self.select = self.lst.get_selection()
        self.select.select_iter(ws)

    def getButton(self):
        return self.sidebar_button


class ConsoleLog(Gtk.Widget):
    """Defines a textView and a textBuffer to be used for displaying
    and updating logging information in the appwindow."""

    def __init__(self):
        super(Gtk.Widget, self).__init__()

        self.textBuffer = Gtk.TextBuffer()
        self.textBuffer.new()
        self.textBuffer.set_text("LOG. Please run Faraday with the --debug "
                                 "flag for more verbose output \0", -1)

        self.textView = Gtk.TextView()
        self.textView.set_editable(False)
        self.textView.set_monospace(True)
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
        self.update(text)

    def update(self, event):
        """Updates the textBuffer with the event sent. Also scrolls to last
        posted automatically"""
        last_position = self.textBuffer.get_end_iter()
        self.textBuffer.insert(last_position, event+"\n", len(event + "\n"))
        insert = self.textBuffer.get_insert()
        self.textView.scroll_to_mark(insert, 0, False, 1, 1)


class Statusbar(Gtk.Widget):
    def __init__(self, on_button_do):
        super(Gtk.Widget, self).__init__()
        """Creates a button with zero ("0") as label"""
        self.callback = on_button_do
        self.button_label_int = 0
        self.button = Gtk.Button.new_with_label(str(self.button_label_int))
        self.button.connect("clicked", self.callback)

    def inc_button_label(self):
        """increments the label by one"""
        self.button_label_int += 1
        self.button.set_label(str(self.button_label_int))
