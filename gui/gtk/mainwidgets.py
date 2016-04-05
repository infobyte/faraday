import gi

gi.require_version('Gtk', '3.0')

from gi.repository import Gtk


class Sidebar(Gtk.Widget):

    def __init__(self, workspace_manager):
        self.ws_manager = workspace_manager

    def createTitle(self):
        title = Gtk.Label()
        title.set_text("Workspaces")
        return title

    def workspaceModel(self):
        workspace_list_info = Gtk.ListStore(str)
        for ws in self.ws_manager.getWorkspacesNames():
            workspace_list_info.append([ws])
        return workspace_list_info

    def workspaceView(self, ws_model):
        lst = Gtk.TreeView(ws_model)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Workspaces", renderer, text=0)
        lst.append_column(column)

        selection = plugin_list_view.get_selection()
        selection.connect("changed", self.on_plugin_selection)

        return lst

    def on_workspace_selection(self, workspace):
        pass

    def getWSList(self):
        return self.workspaceView(self.workspaceModel())


