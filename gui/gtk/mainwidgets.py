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

    def __init__(self, workspace_manager, callback_to_change_workspace, conf):
        super(Gtk.Widget, self).__init__()
        self.callback = callback_to_change_workspace
        self.ws_manager = workspace_manager
        self.lastWorkspace = conf
        self.workspace_list_info = Gtk.ListStore(str)

        self.workspaceModel()
        self.workspaceView(self.workspace_list_info)

    def createTitle(self):
        title = Gtk.Label()
        title.set_text("Workspaces")
        return title

    def workspaceModel(self):
        for ws in self.ws_manager.getWorkspacesNames():
            treeIter = self.workspace_list_info.append([ws])
            if ws == self.lastWorkspace:
                self.defaultSelection = treeIter

    def workspaceView(self, ws_model):
        self.lst = Gtk.TreeView(ws_model)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Workspaces", renderer, text=0)
        self.lst.append_column(column)

        # select by default the last active workspace
        if self.defaultSelection is not None:
            self.selectDefault = self.lst.get_selection()
            self.selectDefault.select_iter(self.defaultSelection)

        self.selection = self.lst.get_selection()
        self.selection.connect("changed", self.callback)

    def addWorkspace(self, ws):
        print"HOLA"
        self.workspace_list_info.append([ws])

    def getSelectedWs(self):
        return self.selection

    def getWSList(self):
        return self.workspaceView(self.workspaceModel())


class ConsoleLog(Gtk.Widget):
    """Defines a textView and a textBuffer to be used for displaying
    and updating logging information in the appwindow"""

    def __init__(self):
        super(Gtk.Widget, self).__init__()

        self.textBuffer = Gtk.TextBuffer()
        self.textBuffer.new()
        self.textBuffer.set_text("FARADAY \0", -1)

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
        """Updates the textBuffer with the event sent"""
        last_position = self.textBuffer.get_end_iter()
        self.textBuffer.insert(last_position, event+"\n", len(event + "\n"))

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
