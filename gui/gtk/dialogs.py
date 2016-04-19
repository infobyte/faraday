# -*- coding: utf-8 -*-
import gi
import re

gi.require_version('Gtk', '3.0')

from gi.repository import Gtk, GdkPixbuf, Gdk
from persistence.persistence_managers import CouchDbManager
from utils.common import checkSSL
from config.configuration import getInstanceConfiguration


CONF = getInstanceConfiguration()

"""This could probably be made much better with just a little effort.
It'd be probably a good idea to make a super class Dialog from which
all the dialogs inherit from with the common methods used (particularly the
OK and Cancel buttons). Good starting point if we continue on with the idea
of using GTK.

Update: so it seems like Gtk actually already provides a Gtk.Dialog class
which would seem practical. All dialogs are already made and it is a
convenience class only, but if there's need to add more, it's a good
thing to know"""


class PreferenceWindowDialog(Gtk.Window):
    """Sets up a preference dialog with basically nothing more than a
    label, a text entry to input your CouchDB IP and a couple of buttons.
    Takes a callback function to the mainapp so that it can refresh the
    workspace list and information"""

    def __init__(self, callback, parent):
        Gtk.Window.__init__(self, title="Preferences")
        self.set_size_request(50, 50)
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.timeout_id = None
        self.reloadWorkspaces = callback

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.add(vbox)

        self.label = Gtk.Label()
        self.label.set_text("Your Couch IP")
        vbox.pack_start(self.label, True, False, 0)

        couch_uri = CONF.getCouchURI()
        self.entry = Gtk.Entry()
        text = couch_uri if couch_uri else "http://127.0.0.1:5050"
        self.entry.set_text(text)
        vbox.pack_start(self.entry, True, False, 0)

        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        vbox.pack_end(hbox, False, True, 0)

        self.OK_button = Gtk.Button.new_with_label("OK")
        self.OK_button.connect("clicked", self.on_click_OK)

        hbox.pack_start(self.OK_button, False, True, 0)

        self.cancel_button = Gtk.Button.new_with_label("Cancel")
        self.cancel_button.connect("clicked", self.on_click_cancel)
        hbox.pack_end(self.cancel_button, False, True, 0)

    def on_click_OK(self, button):
        """Defines what happens when user clicks OK button"""
        repourl = self.entry.get_text()
        if not CouchDbManager.testCouch(repourl):
            errorDialog(self, "The provided URL is not valid",
                        "Are you sure CouchDB is running?")
        elif repourl.startswith("https://"):
            if not checkSSL(repourl):
                errorDialog("The SSL certificate validation has failed")
        else:
            CONF.setCouchUri(repourl)
            CONF.saveConfig()
            self.reloadWorkspaces()
            self.destroy()

    def on_click_cancel(self, button):
        self.destroy()


class NewWorkspaceDialog(Gtk.Window):
    """Sets up the New Workspace Dialog, where the user can set a name,
    a description and a type for a new workspace. Also checks that the
    those attributes don't correspond to an existing workspace"""

    def __init__(self, callback,  workspace_manager, sidebar, parent):

        Gtk.Window.__init__(self, title="Create New Workspace")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_size_request(200, 200)
        self.timeout_id = None
        self.callback = callback
        self.sidebar = sidebar

        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        self.nameBox = Gtk.Box(spacing=6)
        self.name_label = Gtk.Label()
        self.name_label.set_text("Name: ")
        self.name_entry = Gtk.Entry()
        self.nameBox.pack_start(self.name_label, False, False, 10)
        self.nameBox.pack_end(self.name_entry, True, True, 10)
        self.nameBox.show()

        self.descrBox = Gtk.Box(spacing=6)
        self.descr_label = Gtk.Label()
        self.descr_label.set_text("Description: ")
        self.descr_entry = Gtk.Entry()
        self.descrBox.pack_start(self.descr_label, False, False, 10)
        self.descrBox.pack_end(self.descr_entry, True, True, 10)
        self.descrBox.show()

        self.typeBox = Gtk.Box(spacing=6)
        self.type_label = Gtk.Label()
        self.type_label.set_text("Type: ")
        self.comboBox = Gtk.ComboBoxText()
        for w in workspace_manager.getAvailableWorkspaceTypes():
            self.comboBox.append_text(w)
        self.typeBox.pack_start(self.type_label, False, False, 10)
        self.typeBox.pack_end(self.comboBox, True, True, 10)
        self.typeBox.show()

        self.buttonBox = Gtk.Box(spacing=6)
        self.OK_button = Gtk.Button.new_with_label("OK")
        self.OK_button.connect("clicked", self.on_click_OK)
        self.cancel_button = Gtk.Button.new_with_label("Cancel")
        self.cancel_button.connect("clicked", self.on_click_cancel)
        self.buttonBox.pack_start(self.OK_button, False, False, 10)
        self.buttonBox.pack_end(self.cancel_button, False, False, 10)
        self.buttonBox.show()

        self.mainBox.pack_start(self.nameBox, False, False, 0)
        self.mainBox.pack_start(self.descrBox, False, False, 0)
        self.mainBox.pack_start(self.typeBox, False, False, 0)
        self.mainBox.pack_end(self.buttonBox, False, False, 0)

        self.mainBox.show()
        self.add(self.mainBox)

    def on_click_OK(self, button):
        letters_or_numbers = r"^[a-z][a-z0-9\_\$()\+\-\/]*$"
        res = re.match(letters_or_numbers, str(self.name_entry.get_text()))
        if res:
            if self.callback is not None:
                self.__name_txt = str(self.name_entry.get_text())
                self.__desc_txt = str(self.descr_entry.get_text())
                self.__type_txt = str(self.comboBox.get_active_text())
                self.callback(self.__name_txt,
                              self.__desc_txt,
                              self.__type_txt)
                self.sidebar.addWorkspace(self.__name_txt)
                self.destroy()
        else:
            errorDialog(self, "Invalid workspace name",
                        "A workspace must be named with "
                        "all lowercase letters (a-z), digi"
                        "ts(0-9) or any of the _$()+-/ "
                        "characters. The name has to start"
                        " with a lowercase letter")

    def on_click_cancel(self, button):
        self.destroy()


class PluginOptionsDialog(Gtk.Window):
    """The dialog where the user can see details about installed plugins.
    It is not the prettiest thing in the world but it works.
    Creating and displaying the models of each plugin settings is specially
    messy, there's more info in the appropiate methods"""
    def __init__(self, plugin_manager, parent):

        Gtk.Window.__init__(self, title="Plugins Options")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_size_request(400, 400)

        if plugin_manager is not None:
            self.plugin_settings = plugin_manager.getSettings()
        else:
            self.plugin_settings = {}

        self.settings_view = None
        self.id_of_selected = "Acunetix XML Output Plugin"  # first one by name
        self.models = self.createPluginsSettingsModel()
        self.setSettingsView()

        plugin_info = self.createPluginInfo(plugin_manager)
        pluginList = self.createPluginListView(plugin_info)
        scroll_pluginList = Gtk.ScrolledWindow(None, None)
        scroll_pluginList.add(pluginList)
        scroll_pluginList.set_min_content_width(300)
        pluginListBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        pluginListBox.pack_start(scroll_pluginList, True, True, 0)

        buttonBox = Gtk.Box()
        OK_button = Gtk.Button.new_with_label("OK")
        cancel_button = Gtk.Button.new_with_label("Cancel")
        OK_button.connect("clicked", self.on_click_OK, plugin_manager)
        cancel_button.connect("clicked", self.on_click_cancel)
        buttonBox.pack_start(OK_button, True, True, 0)
        buttonBox.pack_start(cancel_button, True, True, 0)
        pluginListBox.pack_start(buttonBox, False, False, 0)

        infoBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        nameBox, versionBox, pluginVersionBox = [Gtk.Box() for i in range(3)]

        nameLabel, versionLabel, pluginVersionLabel = [Gtk.Label()
                                                       for i in range(3)]

        self.nameEntry, self.versionEntry, self.pluginVersionEntry = [
                Gtk.Label() for i in range(3)]

        nameLabel.set_text("Name: ")
        versionLabel.set_text("Version: ")
        pluginVersionLabel.set_text("Plugin version: ")

        nameBox.pack_start(nameLabel, False, False, 5)
        nameBox.pack_start(self.nameEntry, False, True, 5)
        versionBox.pack_start(versionLabel, False, False, 5)
        versionBox.pack_start(self.versionEntry, False, True, 5)
        pluginVersionBox.pack_start(pluginVersionLabel, False, False, 5)
        pluginVersionBox.pack_start(self.pluginVersionEntry, False, True, 5)

        infoBox.pack_start(nameBox, False, False, 5)
        infoBox.pack_start(versionBox, False, False, 5)
        infoBox.pack_start(pluginVersionBox, False, False, 5)

        self.pluginSpecsBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.pluginSpecsBox.pack_start(infoBox, False, False, 5)
        self.pluginSpecsBox.pack_start(self.settings_view, True, True, 0)

        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        self.mainBox.pack_start(pluginListBox, True, True, 5)
        self.mainBox.pack_end(self.pluginSpecsBox, False, True, 5)

        self.add(self.mainBox)

    def on_click_OK(self, button, plugin_manager):
        if plugin_manager is not None:
            plugin_manager.updateSettings(self.plugin_settings)
        self.destroy()

    def on_click_cancel(self, button):
        self.destroy()

    def create_entry_box(self, plugin_name, plugin_tool, plugin_version):
        entry_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        self.name_entry = Gtk.Entry()
        self.name_entry.set_text(plugin_name)
        self.name_entry.set_editable(False)

        self.tool_entry = Gtk.Entry()
        self.tool_entry.set_text(plugin_tool)
        self.tool_entry.set_editable(False)

        self.version_entry = Gtk.Entry()
        self.version_entry.set_text(plugin_version)
        self.version_entry.set_editable(False)

        entry_box.pack_start(self.name_entry, True, True, 6)
        entry_box.pack_start(self.tool_entry, True, True, 6)
        entry_box.pack_end(self.version_entry, True, True, 6)

        return entry_box

    def createPluginInfo(self, plugin_manager):
        """Creates and return a TreeStore where the basic information about
        the plugins live"""
        plugin_info = Gtk.TreeStore(str, str, str, str)

        for plugin_id, params in self.plugin_settings.iteritems():
            plugin_info.append(None, [plugin_id,
                                      params["name"],
                                      params["version"],
                                      params["plugin_version"]])

        sorted_plugin_info = Gtk.TreeModelSort(model=plugin_info)
        sorted_plugin_info.set_sort_column_id(1, Gtk.SortType.ASCENDING)
        return sorted_plugin_info

    def createPluginListView(self, plugin_info):
        """Creates the view for the left-hand side list of the dialog.
        It uses an instance of the plugin manager to get a list
        of all available plugins"""

        plugin_list_view = Gtk.TreeView(plugin_info)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Title", renderer, text=1)
        column.set_sort_column_id(1)
        plugin_list_view.append_column(column)

        selection = plugin_list_view.get_selection()
        selection.connect("changed", self.on_plugin_selection)

        return plugin_list_view

    def createPluginsSettingsModel(self):
        """Creates a dictionary with
        {plugin-name : [(setting-name, setting-value)]} structure. This is used
        to hold all the plugins settings models"""

        models = {}

        for plugin_id in self.plugin_settings.iteritems():
            plugin_info = plugin_id[1]
            store = Gtk.ListStore(str, str)
            for setting in plugin_info["settings"].items():
                setting_name = setting[0]
                setting_value = setting[1]
                store.append([setting_name, setting_value])
            models[plugin_id[1]["name"]] = store
        return models

    def createAdecuatePluginSettingView(self, store):
        """Create the adecuate plugin settings view. The first time this is
        executed, it will be none and it will tell the view which columns
        to and such. After that, it will just change the model displayed"""
        self.active_store = store

        if self.settings_view is None:
            self.settings_view = Gtk.TreeView(store)
            renderer_text = Gtk.CellRendererText()
            column_text = Gtk.TreeViewColumn("Settings", renderer_text, text=0)
            self.settings_view.append_column(column_text)

            renderer_editable_text = Gtk.CellRendererText()
            renderer_editable_text.set_property("editable", True)
            renderer_editable_text.connect("edited", self.value_changed)
            column_editabletext = Gtk.TreeViewColumn("Value",
                                                     renderer_editable_text,
                                                     text=1)

            self.settings_view.append_column(column_editabletext)

        else:
            self.settings_view.set_model(store)

    def value_changed(self, widget, path, text):
        self.active_store[path][1] = text
        setting = self.active_store[path][0]
        settings = self.plugin_settings[self.name_of_selected]["settings"]
        settings[setting.strip()] = text.strip()

    def on_plugin_selection(self, selection):
        """When the user selects a plugin, it will change the text
        displeyed on the entries to their corresponding values"""

        model, treeiter = selection.get_selected()
        self.id_of_selected = model[treeiter][1]
        self.name_of_selected = model[treeiter][0]

        self.setSettingsView()

        self.nameEntry.set_label(model[treeiter][1])
        self.versionEntry.set_label(model[treeiter][2])
        self.pluginVersionEntry.set_label(model[treeiter][3])

    def setSettingsView(self):
        adecuateModel = self.models[self.id_of_selected]
        self.createAdecuatePluginSettingView(adecuateModel)


class NotificationsDialog(Gtk.Window):
    def __init__(self, view, callback, parent):
        Gtk.Window.__init__(self, title="Notifications")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_size_request(400, 200)
        self.view = view
        self.destroy_notifications = callback

        self.button = Gtk.Button()
        self.button.set_label("OK")
        self.button.connect("clicked", self.on_click_OK)

        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.mainBox.pack_start(self.view, True, True, 0)
        self.mainBox.pack_start(self.button, False, False, 0)

        self.add(self.mainBox)

    def on_click_OK(self, button):
        self.destroy_notifications()
        self.destroy()


class aboutDialog(Gtk.AboutDialog):
    """The simple about dialog displayed when the user clicks on "about"
    ont the menu. Could be in application.py, but for consistency reasons
    its here"""
    def __init__(self, main_window):

        Gtk.AboutDialog.__init__(self, transient_for=main_window, modal=True)
        icons = CONF.getImagePath() + "icons/"
        faraday_icon = GdkPixbuf.Pixbuf.new_from_file(icons+"about.png")
        self.set_logo(faraday_icon)
        self.set_program_name("Faraday")
        self.set_comments("Penetration Test IDE -"
                          " Infobyte LLC. - All rights reserved")
        faraday_website = "http://www.infobytesec.com/faraday.html"
        self.set_website(faraday_website)
        self.set_website_label("Learn more about Faraday")


class helpDialog(Gtk.AboutDialog):
    """Using about dialog 'cause they are very similar, but this will
    display github page, Wiki, and such"""
    def __init__(self, main_window):
        Gtk.AboutDialog.__init__(self, transient_for=main_window, modal=True)
        icons = CONF.getImagePath() + "icons/"
        faraday_icon = GdkPixbuf.Pixbuf.new_from_file(icons+"faraday_icon.png")
        self.set_logo(faraday_icon)
        self.set_program_name("Faraday")
        self.set_comments("Farday is a Penetration Test IDE. "
                          "Just use one of the supported tools on Faraday's "
                          " terminal and a plugin will capture the output and "
                          "extract useful information for you.")
        faraday_website = "https://github.com/infobyte/faraday/wiki"
        self.set_website(faraday_website)
        self.set_website_label("Learn more about how to use Faraday")


class errorDialog(Gtk.MessageDialog):
    """A simple error dialog to show the user where things went wrong.
    Takes the parent window, (Gtk.Window or Gtk.Dialog, most probably)
    the error and explanation (strings, nothing fancy) as arguments"""

    def __init__(self, parent_window, error, explanation=None):
        Gtk.MessageDialog.__init__(self, parent_window, 0,
                                   Gtk.MessageType.ERROR,
                                   Gtk.ButtonsType.OK,
                                   error)
        if explanation is not None:
            self.format_secondary_text(explanation)
        self.run()
        self.destroy()
