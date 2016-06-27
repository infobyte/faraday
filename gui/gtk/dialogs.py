#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import gi
import re
import webbrowser

gi.require_version('Gtk', '3.0')

from gi.repository import Gtk, GdkPixbuf, Gdk
from persistence.persistence_managers import CouchDbManager
from utils.common import checkSSL
from config.configuration import getInstanceConfiguration
from model import guiapi
from decorators import scrollable


CONF = getInstanceConfiguration()


class PreferenceWindowDialog(Gtk.Window):
    """Sets up a preference dialog with basically nothing more than a
    label, a text entry to input your CouchDB IP and a couple of buttons.
    Takes a callback function to the mainapp so that it can refresh the
    workspace list and information"""

    def __init__(self, callback, parent):
        Gtk.Window.__init__(self, title="Preferences")
        self.parent = parent
        self.set_modal(True)
        self.set_size_request(400, 100)
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.connect("key_press_event", key_reactions)
        self.set_transient_for(parent)
        self.reloadWorkspaces = callback

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        ip_label = Gtk.Label()
        ip_label.set_text("Your Couch IP")
        main_box.pack_start(ip_label, True, False, 10)

        couch_uri = CONF.getCouchURI()
        self.ip_entry = Gtk.Entry()
        text = couch_uri if couch_uri else "http://127.0.0.1:5050"
        self.ip_entry.set_text(text)
        main_box.pack_start(self.ip_entry, True, False, 10)

        button_box = Gtk.Box(spacing=6)
        main_box.pack_end(button_box, False, True, 10)

        OK_button = Gtk.Button.new_with_label("OK")
        OK_button.connect("clicked", self.on_click_ok)

        button_box.pack_start(OK_button, False, True, 10)

        cancel_button = Gtk.Button.new_with_label("Cancel")
        cancel_button.connect("clicked", self.on_click_cancel)
        button_box.pack_end(cancel_button, False, True, 10)

        self.add(main_box)

    def on_click_ok(self, button=None):
        """Button is useless, only there because GTK likes it. Takes the
        repourl (Couch IP) from self.ip_entry and connect to it if possible.
        """
        repourl = self.ip_entry.get_text()
        if not CouchDbManager.testCouch(repourl):
            errorDialog(self, "The provided URL is not valid",
                        "Are you sure CouchDB is running?")
        elif repourl.startswith("https://"):
            if not checkSSL(repourl):
                errorDialog(self, "The SSL certificate validation has failed")
        else:
            CONF.setCouchUri(repourl)
            CONF.saveConfig()
            self.reloadWorkspaces()
            self.destroy()

    def on_click_cancel(self, button=None):
        self.destroy()


class NewWorkspaceDialog(Gtk.Window):
    """Sets up the New Workspace Dialog, where the user can set a name,
    a description and a type for a new workspace. Also checks that the
    those attributes don't correspond to an existing workspace"""

    def __init__(self, create_ws_callback,  workspace_manager, sidebar, parent,
                 title=None):

        Gtk.Window.__init__(self, title="Create New Workspace")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_modal(True)
        self.connect("key_press_event", key_reactions)
        self.set_size_request(200, 200)
        self.create_ws_callback = create_ws_callback
        self.sidebar = sidebar
        self.workspace_manager = workspace_manager
        self.title = title

        self.warning_label = self.create_warning_label()
        self.main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)

        name_box = self.create_name_box()
        description_box = self.create_description_box()
        type_box = self.create_type_box()
        button_box = self.create_button_box()

        self.main_box.pack_start(name_box, False, False, 10)
        self.main_box.pack_start(description_box, False, False, 10)
        self.main_box.pack_start(type_box, False, False, 10)
        self.main_box.pack_start(self.warning_label, False, False, 10)
        self.main_box.pack_end(button_box, False, False, 10)

        self.main_box.show()
        self.add(self.main_box)

    def create_name_box(self):
        """Return a box with a Name label left of an entry."""
        name_box = Gtk.Box(spacing=6)
        name_label = Gtk.Label()
        name_label.set_text("Name: ")
        self.name_entry = Gtk.Entry()
        if self.title is not None:
            self.name_entry.set_text(title)
        name_box.pack_start(name_label, False, False, 10)
        name_box.pack_end(self.name_entry, True, True, 10)
        return name_box

    def create_description_box(self):
        """Return a box with a Description label left of an entry."""
        description_box = Gtk.Box(spacing=6)
        description_label = Gtk.Label()
        description_label.set_text("Description: ")
        self.description_entry = Gtk.Entry()
        description_box.pack_start(description_label, False, False, 10)
        description_box.pack_end(self.description_entry, True, True, 10)
        return description_box

    def create_type_box(self):
        """Return a box with a Type label left of a combo box"""
        type_box = Gtk.Box(spacing=6)
        type_label = Gtk.Label()
        type_label.set_text("Type: ")
        self.type_comboBox = Gtk.ComboBoxText()
        self.type_comboBox.connect("changed", self.on_select_ws_type)
        for w in self.workspace_manager.getAvailableWorkspaceTypes():
            self.type_comboBox.append_text(w)
        self.type_comboBox.set_active(0)
        type_box.pack_start(type_label, False, False, 10)
        type_box.pack_end(self.type_comboBox, True, True, 10)
        return type_box

    def create_warning_label(self):
        """Return a label with a warning if the user has FS selected as the
        desired WS type.
        """
        warning_label = Gtk.Label()
        warning_label.set_no_show_all(True)
        warning_label.set_markup("<b>WARNING: </b> The FS (Filesystem) "
                                 "databases are deprecated and strongly "
                                 "discouraged. \n You will <b>not</b> be able "
                                 "to edit the information provided by Faraday "
                                 "with a FileSystem DB. \n Please "
                                 "set up CouchDB and use it as the database "
                                 "for your workspaces.")
        return warning_label

    def create_button_box(self):
        """Return a box with OK and cancel buttons."""
        button_box = Gtk.Box(spacing=6)
        OK_button = Gtk.Button.new_with_label("OK")
        OK_button.connect("clicked", self.on_click_ok)
        cancel_button = Gtk.Button.new_with_label("Cancel")
        cancel_button.connect("clicked", self.on_click_cancel)
        button_box.pack_start(OK_button, False, False, 10)
        button_box.pack_end(cancel_button, False, False, 10)
        return button_box

    def on_click_ok(self, button=None):
        """Check if the name provided for the WS is valid. If so,
        create it and add it to the sidebar. If not, show error.
        """
        letters_or_numbers = r"^[a-z][a-z0-9\_\$()\+\-\/]*$"
        res = re.match(letters_or_numbers, str(self.name_entry.get_text()))
        if res:
            ws_name = str(self.name_entry.get_text())
            ws_desc = str(self.description_entry.get_text())
            ws_type = str(self.type_comboBox.get_active_text())
            creation_ok = self.create_ws_callback(ws_name,
                                                  ws_desc,
                                                  ws_type)
            if creation_ok:
                self.sidebar.addWorkspace(ws_name)
            else:
                errorDialog(self, "Something went wrong when creating "
                                  "the new workspace.")
            self.destroy()
        else:
            errorDialog(self, "Invalid workspace name",
                        "A workspace must be named with "
                        "all lowercase letters (a-z), digi"
                        "ts(0-9) or any of the _$()+-/ "
                        "characters. The name has to start"
                        " with a lowercase letter")

    def on_select_ws_type(self, combo_box):
        if combo_box.get_active_text() == 'FS':
            self.warning_label.show()
        else:
            self.warning_label.hide()

    def on_click_cancel(self, button):
        self.destroy()


class PluginOptionsDialog(Gtk.Window):
    """The dialog where the user can see details about installed plugins.
    It is not the prettiest thing in the world but it works.
    Creating and displaying the models of each plugin settings is specially
    messy , there's more info in the appropiate methods"""
    # TODO: probably stop hardcoding the first plugin, right?

    def __init__(self, plugin_manager, parent):

        Gtk.Window.__init__(self, title="Plugins Options")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_modal(True)
        self.connect("key_press_event", key_reactions)
        self.set_size_request(800, 300)
        self.plugin_manager = plugin_manager

        if plugin_manager is not None:
            self.plugin_settings = plugin_manager.getSettings()
        else:
            self.plugin_settings = {}

        self.settings_view = None
        self.id_of_selected = "Acunetix XML Output Plugin"  # first one by name
        self.models = self.createPluginsSettingsModel()
        self.setSettingsView()

        plugin_info = self.createPluginInfo(plugin_manager)
        plugin_list = self.createPluginListView(plugin_info)
        left_side_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        left_side_box.pack_start(plugin_list, True, True, 0)

        buttonBox = Gtk.Box()
        OK_button = Gtk.Button.new_with_label("OK")
        cancel_button = Gtk.Button.new_with_label("Cancel")
        OK_button.connect("clicked", self.on_click_ok)
        cancel_button.connect("clicked", self.on_click_cancel)
        buttonBox.pack_start(OK_button, True, True, 10)
        buttonBox.pack_start(cancel_button, True, True, 10)

        left_side_box.pack_start(buttonBox, False, False, 10)

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
        self.mainBox.pack_start(left_side_box, False, True, 10)
        self.mainBox.pack_end(self.pluginSpecsBox, True, True, 10)

        self.add(self.mainBox)

    def on_click_ok(self, button=None):
        """On click OK button update the plugins settings and then destroy"""
        if self.plugin_manager is not None:
            self.plugin_manager.updateSettings(self.plugin_settings)
        self.destroy()

    def on_click_cancel(self, button):
        """On click cancel button, destroy brutally. No mercy"""
        self.destroy()

    def createPluginInfo(self, plugin_manager):
        """Creates and return a TreeStore where the basic information about
        the plugins: the plugin ID, name, intended version of the tool
        and plugin version"""
        plugin_info = Gtk.TreeStore(str, str, str, str)

        for plugin_id, params in self.plugin_settings.iteritems():
            plugin_info.append(None, [plugin_id,
                                      params["name"],
                                      params["version"],  # tool version
                                      params["plugin_version"]])

        # Sort it!
        sorted_plugin_info = Gtk.TreeModelSort(model=plugin_info)
        sorted_plugin_info.set_sort_column_id(1, Gtk.SortType.ASCENDING)
        return sorted_plugin_info

    @scrollable(width=300)
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
            # iter through the plugins
            plugin_info = plugin_id[1]  # get dictionary associated to plugin
            store = Gtk.ListStore(str, str)  # create the store for that plugin

            # iter through settings dictionary
            for setting in plugin_info["settings"].items():
                setting_name = setting[0]
                setting_value = setting[1]
                store.append([setting_name, setting_value])

            models[plugin_id[1]["name"]] = store  # populate dict with store
        return models

    def createAdecuatePluginSettingView(self, store):
        """Create the adecuate plugin settings view. The first time this is
        executed, it will be none and it will tell the view which columns
        to display. After that, it will just change the model displayed"""
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
        """Save new settings"""
        self.active_store[path][1] = text
        setting = self.active_store[path][0]
        settings = self.plugin_settings[self.name_of_selected]["settings"]
        settings[setting.strip()] = text.strip()

    def on_plugin_selection(self, selection):
        """When the user selects a plugin, it will change the text
        displeyed on the entries to their corresponding values"""

        # if the user searches for something that doesn't exists,
        # for example, the plugin 'jsaljfdlajs', this avoids
        # the program trying to get settings for that non-existing plugin
        try:
            model, treeiter = selection.get_selected()
            self.name_of_selected = model[treeiter][0]
            self.id_of_selected = model[treeiter][1]
            tool_version = model[treeiter][2]
            plugin_version = model[treeiter][3]

            self.setSettingsView()

            self.nameEntry.set_label(self.name_of_selected)

            if tool_version:
                self.versionEntry.set_label(tool_version)
            else:
                self.versionEntry.set_label("")

            if plugin_version:
                self.pluginVersionEntry.set_label(plugin_version)
            else:
                self.pluginVersionEntry.set_label("")
        except TypeError:
            pass

    def setSettingsView(self):
        """Makes the window match the selected plugin with the settings
        displayed"""

        adecuateModel = self.models[self.id_of_selected]
        self.createAdecuatePluginSettingView(adecuateModel)


class HostInfoDialog(Gtk.Window):
    """Sets the blueprints for a simple host info window. It will display
    basic information in labels as well as interfaces/services in a treeview.

    While working in this class, keep in mind the distinction between
    selections (which are part of a model that holds data about an object as
    strings and ints) and the object per se, which are in the model folder and
    are totally alien to GTK.
    """
    def __init__(self, parent, active_ws_name, is_ws_couch, host):
        """Creates a window with the information about a given hosts.
        The parent is needed so the window can set transient for
        """

        window_title = "Host " + host.name + " information"
        Gtk.Window.__init__(self, title=window_title)

        self.set_transient_for(parent)
        self.set_size_request(1200, 500)
        self.set_modal(True)
        self.connect("key_press_event", key_reactions)

        self.is_ws_couch = is_ws_couch

        self.host = host
        self.model = self.create_model(self.host)
        host_info = self.model[0]

        host_id = self.model[0][0]
        couch_url = CONF.getCouchURI()
        base_url = couch_url + "/reports/_design/reports/index.html#/host/ws/"
        self.edit_url = base_url + active_ws_name + "/hid/" + host_id

        host_info_frame = self.create_host_info_frame(host_info)

        self.specific_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.specific_info_frame = self.create_scroll_frame(
                                       self.specific_info,
                                       "Service Information")

        self.vuln_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.vuln_info_frame = self.create_scroll_frame(
                                            self.vuln_info,
                                            "Vulnerability Information")

        main_tree = self.create_main_tree_view(self.model)
        vuln_list = self.create_vuln_list()

        button_box = self.create_button_box()

        main_box = Gtk.Box()

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        info_box.pack_start(host_info_frame, True, True, 10)
        info_box.pack_start(self.specific_info_frame, True, True, 10)
        info_box.pack_start(self.vuln_info_frame, True, True, 10)
        info_box.pack_start(button_box, False, False, 10)

        main_tree_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_tree_box.pack_start(main_tree, True, True, 10)
        main_tree_box.pack_start(Gtk.Box(), False, False, 10)

        vuln_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        vuln_list_box.pack_start(vuln_list, True, True, 10)
        vuln_list_box.pack_start(Gtk.Box(), False, False, 10)

        main_box.pack_start(main_tree_box, False, False, 5)
        main_box.pack_start(vuln_list_box, False, False, 0)
        main_box.pack_start(info_box, True, True, 5)

        self.add(main_box)

    def create_button_box(self):
        """Creates an horizontal box to hold the buttons."""
        button_box = Gtk.Box()

        ok_button = Gtk.Button.new_with_label("OK")
        ok_button.connect("clicked", self.on_click_ok)

        html_edit_url = '<a href="' + self.edit_url + '"> Edit host </a>'
        edit_button = Gtk.Button()
        edit_label = Gtk.Label()
        edit_label.set_markup(html_edit_url)
        edit_button.add(edit_label)
        edit_button.connect("clicked", self.on_edit_host)
        if not self.is_ws_couch:
            edit_button.set_sensitive(False)
            edit_button.set_tooltip_text("You need to be on a CouchDB "
                                         "workspace to edit information")

        button_box.pack_start(edit_button, True, True, 0)
        button_box.pack_start(ok_button, True, True, 0)
        return button_box

    def on_edit_host(self, button):
        """Tries to open self.edit_url (url which directs to the host in the
        web ui) in the default browser."""
        webbrowser.open(self.edit_url, new = 2)


    def create_scroll_frame(self, inner_box, label_str):
        """Create a scrollable frame containing inner_box and with label_str
        as its title.
        """

        label = Gtk.Label()
        label.set_markup("<big>" + label_str + "</big>")

        scroll_box = Gtk.ScrolledWindow(None, None)
        scroll_box.set_overlay_scrolling(False)
        scroll_box.set_policy(Gtk.PolicyType.AUTOMATIC,
                              Gtk.PolicyType.ALWAYS)

        scroll_box.add(inner_box)

        frame = Gtk.Frame()
        frame.set_label_widget(label)
        frame.add(scroll_box)

        return frame

    def create_host_info_frame(self, host_info):
        """Return a box where the basic information about the host
        lives in labels. It include names, OS, Owned status and vulnerability
        count.
        """
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        prop_names = self.get_properties_names("Host")
        self.show_info_in_box(host_info, prop_names, box)

        host_info_frame = self.create_scroll_frame(box, "Host Information")

        return host_info_frame

    @scrollable(width=250)
    def create_vuln_list(self):
        """Creates a simple view of vulnerabilities for the object
        and returns a box containing it. The vuln_list will be a value of the
        instance.
        """

        self.vuln_list = Gtk.TreeView()
        self.vuln_list.set_activate_on_single_click(True)
        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Vulnerabilities", renderer, text=1)
        column.set_sort_column_id(1)
        self.vuln_list.append_column(column)

        vuln_selection = self.vuln_list.get_selection()
        vuln_selection.connect("changed", self.on_vuln_selection)

        return self.vuln_list

    def create_model(self, host):
        """Return a model for the given host. It holds quite a bit of info.
        It has 15 columns holding the host ID and name as parent,
        all the information about the interfaces of that host and all the
        information about the services of those interfaces.

        The model is difficult to draw because of its nested nature, but
        you can think of it like this, keeping in mind each node has
        several columns

          HOST
          -----> INTERFACE1
                   ------------> SERVICE1
                   ------------> SERVICE2
          -----> INTERFACE2
                   -----------> SERVICE1
                   -----------> SERVICE2

        And so on and so on, like Zizek says.
        """

        # those are 13 strings
        model = Gtk.TreeStore(str, str, str, str, str, str, str,
                              str, str, str, str, str, str)

        # GTK is very strict about how many columns the model has.
        # only the ID and the name are needed, but i still need to 'fill'
        # the other columns with dummy info

        display_str = host.getName() + " (" + str(len(host.getVulns())) + ")"
        owned_status = ("Yes" if host.isOwned() else "No")
        host_position = model.append(None, [host.getID(), host.getName(),
                                            host.getOS(), owned_status,
                                            str(len(host.getVulns())), "",
                                            "", "", "", "", "", "",
                                            display_str])

        # some convenient functions just to separate and clarify what
        # the code does. they are used in the nested for loop directly
        # below them.

        def lst_to_str(lst):
            """Convenient function to avoid this long line everywhere"""
            return ', '.join([str(word) for word in lst if word])

        def add_interface_to_host_in_model(interface, host_pos, model):
            """Append an interface to the host within a model.
            Return the tree_iter represeting the position of the interface
            within the model. Modifies the model.
            """
            ipv4_dic = interface.getIPv4()
            ipv6_dic = interface.getIPv6()
            vulns = interface.getVulns()
            display_str = interface.getName() + " (" + str(len(vulns)) + ")"

            position = model.append(host_pos, [interface.getID(),
                                               interface.getName(),
                                               interface.getDescription(),
                                               interface.getMAC(),
                                               ipv4_dic['mask'],
                                               ipv4_dic['gateway'],
                                               lst_to_str(ipv4_dic['DNS']),
                                               ipv4_dic['address'],
                                               ipv6_dic['prefix'],
                                               ipv6_dic['gateway'],
                                               lst_to_str(ipv6_dic['DNS']),
                                               ipv6_dic['address'],
                                               display_str])
            return position

        def add_service_to_interface_in_model(service, interface_pos, model):
            """Append a service to an interface at interface_pos in the given
            model. Return None. Modifies the model"""
            vulns = service.getVulns()
            display_str = service.getName() + " (" + str(len(vulns)) + ")"
            model.append(interface_pos, [service.getID(),
                                         service.getName(),
                                         service.getDescription(),
                                         service.getProtocol(),
                                         service.getStatus(),
                                         lst_to_str(service.getPorts()),
                                         service.getVersion(),
                                         "Yes" if service.isOwned() else "No",
                                         "", "", "", "", display_str])

        interfaces = host.getAllInterfaces()
        for interface in interfaces:
            interface_position = add_interface_to_host_in_model(interface,
                                                                host_position,
                                                                model)
            services = interface.getAllServices()
            for service in services:
                add_service_to_interface_in_model(service, interface_position,
                                                  model)

        return model

    @scrollable(width=250)
    def create_main_tree_view(self, model):
        """Return a box containing the main tree (the one showing
        Host/Interfaces/Services) as its content.
        """
        view = Gtk.TreeView(model)
        view.set_activate_on_single_click(True)
        view.set_enable_tree_lines(True)
        view.expand_all()

        renderer = Gtk.CellRendererText()
        column = Gtk.TreeViewColumn("Host/Interfaces/Services",
                                    renderer, text=12)

        view.append_column(column)
        view.set_expander_column(column)
        selection = view.get_selection()
        selection.connect("changed", self.on_main_tree_selection)

        return view

    def on_main_tree_selection(self, tree_selection):
        """Fire up neccesary actions when selection on the main tree changes"""
        model, tree_iter = tree_selection.get_selected()
        object_info = model[tree_iter]

        iter_depth = model.iter_depth(tree_iter)
        object_type = {0: 'Host', 1: 'Interface', 2: 'Service'}[iter_depth]

        if object_type == 'Host':
            self.set_vuln_model(self.create_vuln_model(self.host))

        elif object_type == 'Interface' or object_type == 'Service':
            self.clear(self.specific_info)
            self.change_label_in_frame(self.specific_info_frame, object_type)
            prop_names = self.get_properties_names(object_type)
            self.show_info_in_box(object_info, prop_names, self.specific_info)
            actual_object = self.get_object(object_info, object_type)
            vuln_model = self.create_vuln_model(actual_object)
            self.set_vuln_model(vuln_model)

    def on_vuln_selection(self, vuln_selection):
        """Fill the vuln_info box with the vulnerability selected.

        The try/except block is necesary 'cause GTK
        is silly (ie: doesn't behave like it would be best for me now)
        and will emit the selection changed signal if the model
        changes even if nothing is selected.
        """

        model, vuln_iter = vuln_selection.get_selected()
        try:
            selected = model[vuln_iter]
            vuln_type = selected[0]
            self.clear(self.vuln_info)
            is_vuln_web = vuln_type == "VulnerabilityWeb"
            frame_title = "Vulnerability Web" if is_vuln_web else "Vulnerability"
            self.change_label_in_frame(self.vuln_info_frame,
                                       frame_title)
            prop_names = self.get_properties_names(vuln_type)
            self.show_info_in_box(selected, prop_names,
                                  self.vuln_info)
        except TypeError:
            return False

    def set_vuln_model(self, model):
        """Sets the vulnerability view to show the given model"""
        self.vuln_list.set_model(model)

    def create_vuln_model(self, obj):
        """Return the model for the vulnerabilities of the obj object.
        It will be sorted alphabetically.
        """
        # those are 15 strings
        model = Gtk.ListStore(str, str, str, str, str, str, str, str,
                              str, str, str, str, str, str, str)

        vulns = obj.getVulns()
        for vuln in vulns:
            _type = vuln.class_signature
            if _type == "Vulnerability":
                # again filling up the model with dumb strings
                # because gtk
                model.append([_type, vuln.getName(), vuln.getDescription(),
                              vuln.getData(), vuln.getSeverity(),
                              ', '.join(vuln.getRefs()),
                              "", "", "", "", "", "", "", "", ""])

            elif _type == "VulnerabilityWeb":
                model.append([_type, vuln.getName(), vuln.getDescription(),
                              vuln.getData(), vuln.getSeverity(),
                              ", ".join(vuln.getRefs()), vuln.getPath(),
                              vuln.getWebsite(), vuln.getRequest(),
                              vuln.getResponse(), vuln.getMethod(),
                              vuln.getPname(), vuln.getParams(),
                              vuln.getQuery(), vuln.getCategory()])
        #sort it!
        sorted_model = Gtk.TreeModelSort(model=model)
        sorted_model.set_sort_column_id(1, Gtk.SortType.ASCENDING)

        return sorted_model

    def change_label_in_frame(self, frame, string):
        """Changes the label in the given frame to 'string Information'"""
        label = frame.get_label_widget()
        label.set_markup("<big>" + string + " " + "Information" + "</big>")

    def show_info_in_box(self, object_info, property_names, box):
        """Appends several boxes vertically to the box. The appended boxes will
        all contain two labels, together forming something like this:
        '<b>property_name:</b> object_info'. It will also append a separator
        on top of each one of these boxes.

        It is important to notice that the first element of object_info
        is ignored. This is because of how the models in this class contain
        information. Thus, there'll be as many of this small boxes as
        len(property_names) minus one, read next paragraph.
        """

        for index, prop_name in enumerate(property_names, start=1):
            if index != 1:
                # do not append to the first prop_name
                separator = Gtk.Separator.new(orientation=Gtk.Orientation.HORIZONTAL)
                box.pack_start(separator, False, True, 0)

            prop_box = Gtk.Box()
            prop_value = object_info[index]

            prop_label = Gtk.Label()
            prop_label.set_markup("<b> %s </b>" % (prop_name))
            prop_label.set_selectable(True)

            value_label = Gtk.Label(prop_value)
            value_label.set_selectable(True)
            prop_box.pack_start(prop_label, False, False, 0)
            prop_box.pack_start(value_label, False, False, 0)
            box.pack_start(prop_box, True, True, 0)

        box.show_all()

    def get_object(self, selected_object, object_type):
        """Take a selection as selected_object and an object_type
        and return the actual object, not the model's selection.
        """
        object_id = selected_object[0]
        if object_type == 'Interface':
            _object = self.host.getInterface(object_id)
        elif object_type == 'Service':
            parent_interface_iter = selected_object.get_parent()
            parent_interface_id = parent_interface_iter[0]
            parent_interface = self.host.getInterface(parent_interface_id)
            _object = parent_interface.childs.get(object_id, None)

        return _object

    def get_properties_names(self, object_type):
        """Return a list with the property names for objects of type
        Interface, Service, Vulnerability and VulnerabilityWeb (passed as a
        string).
        """
        if object_type == "Host":
            property_names = ["Name: ", "OS: ", "Owned: ",
                              "Vulnerabilities: "]

        if object_type == "Interface":
            property_names = ["Name: ", "Description: ", "MAC: ",
                              "IPv4 Mask: ", "IPv4 Gateway: ", "IPv4 DNS: ",
                              "IPv4 Address: ", "IPv6 Prefix: ",
                              "IPv6 Gateway", "IPv6 DNS: ",
                              "IPv6 Address: "]

        elif object_type == "Service":
            property_names = ["Name: ", "Description: ", "Protocol: ",
                              "Status: ", "Port: ", "Version: ", "Is Owned?: "]

        elif object_type == "Vulnerability":
            property_names = ["Name: ", "Description: ", "Data: ",
                              "Severity: ", "Refs: "]

        elif object_type == "VulnerabilityWeb":
            property_names = ["Name: ", "Description: ", "Data: ",
                              "Severity: ", "Refs: ", "Path: ",
                              "Website: ", "Request: ", "Response: ",
                              "Method: ", "Pname: ", "Params: ",
                              "Query: ", "Category: "]
        return property_names

    def clear(self, box):
        """Remove all the widgets from box."""

        def remove(widget, box):
            """Removes widget from box"""
            box.remove(widget)

        box.foreach(remove, box)

    def on_click_ok(self, button=None):
        self.destroy()


class ConflictsDialog(Gtk.Window):
    """Blueprints for a beautiful, colorful, gtk-esque conflicts
    dialog. The user is confronted with two objects, one at the left,
    one at the right, and is able to edit any of the object's properties,
    choosing either one of them with a button"""

    def __init__(self, conflicts, parent):
        """Inits the window with its title and size, presents the
        user with the first conflict found. If there aren't conflict
        an empty window will be presented"""

        Gtk.Window.__init__(self, title="Conflicts")
        self.set_transient_for(parent)
        self.set_size_request(600, 400)
        self.set_modal(True)
        self.connect("key_press_event", key_reactions)
        self.conflicts = conflicts
        self.conflict_n = 0
        self.current_conflict = self.conflicts[self.conflict_n]
        self.view = None

        self.views_box = Gtk.Box()

        # TODO: FIX THIS
        # this is the wrong way to do it, I'm creating a useless gtk.tree
        # so I can know the user's default color background
        # that not being bad enought, get_background_color is deprecated
        dumpy_tree = Gtk.TreeView()
        style = dumpy_tree.get_style_context()
        self.bg_color = style.get_background_color(Gtk.StateFlags.NORMAL)
        self.bg_color = self.bg_color.to_string()

        button_box = self.create_buttons()

        self.models = self.create_conflicts_models(conflicts)
        self.set_conflict_view(self.conflict_n)
        self.current_conflict_model = self.models[self.conflict_n]

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        main_box.pack_start(self.views_box, True, True, 5)
        main_box.pack_start(button_box, False, True, 5)

        self.add(main_box)

    def update_current_conflict_model(self):
        self.current_conflict_model = self.models[self.conflict_n]

    def update_current_conflict(self):
        self.current_conflict = self.conflicts[self.conflict_n]

    def create_buttons(self):
        """Creates and connects the button for the window"""
        button_box = Gtk.Box()
        keep_right = Gtk.Button.new_with_label("Keep RIGHT")
        keep_left = Gtk.Button.new_with_label("Keep LEFT")
        quit = Gtk.Button.new_with_label("Quit")

        keep_right.connect("clicked", self.save, "right")
        keep_left.connect("clicked", self.save, "left")
        quit.connect("clicked", self.on_quit)

        space = Gtk.Box()
        button_box.pack_start(quit, False, False, 5)
        button_box.pack_start(space, True, True, 5)
        button_box.pack_start(keep_left, False, False, 5)
        button_box.pack_start(keep_right, False, False, 5)
        return button_box

    def save(self, button, keeper):
        """Saves information to Faraday. Keeper is needed to know if user
        wanted to keep left or right view"""
        current_conflict_type = self.current_conflict.getModelObjectType()

        # right is represented by column 2 of the model, left by column 1
        if keeper == "right":
            n = 2
        elif keeper == "left":
            n = 1

        # interface needs a special case, 'cause it's the only object
        # which resolveConflict() will expect its solution to have a
        # dicitionary inside the solution dictionary
        if current_conflict_type != "Interface":
            solution = {}
            for row in self.current_conflict_model:
                solution[row[0].lower()] = self.uncook(row[n], row[4])
        else:
            solution = self.case_for_interfaces(self.current_conflict_model, n)

        try:
            guiapi.resolveConflict(self.current_conflict, solution)
            # if this isn't the last conflict...
            if len(self.conflicts)-1 > self.conflict_n:
                self.conflict_n += 1
                self.update_current_conflict()
                self.update_current_conflict_model()
                self.set_conflict_view(self.conflict_n)
            else:
                self.destroy()

        except ValueError:
            dialog = Gtk.MessageDialog(self, 0,
                                       Gtk.MessageType.INFO,
                                       Gtk.ButtonsType.OK,
                                       ("You tried to set some invalid "
                                        "information. Make sure all True/False"
                                        " settings are either True or False, "
                                        "all values that should be numbers are"
                                        " numbers, and so on."))
            dialog.run()
            dialog.destroy()

    def case_for_interfaces(self, model, n):
        """The custom case for the interfaces. Plays a little
        with the information in the given model to create a solution acceptable
        by resolveConflict. n is the right or left view, should be
        either 1 or 2 as integers"""
        solution = {}
        solution["ipv4"] = {}
        solution["ipv6"] = {}
        for row in model:
            prop_name = row[0].lower()
            if prop_name.startswith("ipv4"):
                prop_name = prop_name.split(" ")[1]
                if not prop_name.startswith("dns"):
                    solution["ipv4"][prop_name] = self.uncook(row[n], row[4])
                elif prop_name.startswith("dns"):
                    solution["ipv4"]["DNS"] = self.uncook(row[n], row[4])

            elif prop_name.startswith("ipv6"):
                prop_name = prop_name.split(" ")[1]
                if not prop_name.startswith("dns"):
                    solution["ipv6"][prop_name] = self.uncook(row[n], row[4])
                elif prop_name.startswith("dns"):
                    solution["ipv6"]["DNS"] = self.uncook(row[n], row[4])
            else:
                solution[prop_name] = self.uncook(row[n], row[4])
        return solution

    def on_quit(self, button):
        """Exits the window"""
        self.destroy()

    def set_conflict_view(self, conflict_n):
        """Creates two views for the model corresponding to the conflict number
        n. If first conflict, self.view will be none. If user is past the first
        conflict, self.view will not be none"""

        @scrollable()
        def make_scrollable(view):
            return view

        if self.view is None:

            renderer = Gtk.CellRendererText()

            original_renderer = Gtk.CellRendererText()
            original_renderer.set_property("editable", True)
            original_renderer.connect("edited", self.value_changed, "original")

            conflict_renderer = Gtk.CellRendererText()
            conflict_renderer.set_property("editable", True)
            conflict_renderer.connect("edited", self.value_changed, "conflict")

            prop_column = Gtk.TreeViewColumn("", renderer, text=0,
                                             background=3)

            obj_column = Gtk.TreeViewColumn("ORIGINAL", original_renderer,
                                            text=1, background=3)

            prop2_column = Gtk.TreeViewColumn("", renderer, text=0,
                                              background=3)
            obj2_column = Gtk.TreeViewColumn("CONFLICTING", conflict_renderer,
                                             text=2, background=3)

            self.view = Gtk.TreeView(self.models[conflict_n])
            self.view.append_column(prop_column)
            self.view.append_column(obj_column)
            self.second_view = Gtk.TreeView(self.models[conflict_n])

            self.second_view.append_column(prop2_column)
            self.second_view.append_column(obj2_column)

            scrolled_view = make_scrollable(self.view)
            second_scrolled_view = make_scrollable(self.second_view)

            self.views_box.pack_start(scrolled_view, True, True, 5)
            self.views_box.pack_start(second_scrolled_view, True, True, 5)

        else:
            self.view.set_model(self.models[conflict_n])
            self.second_view.set_model(self.models[conflict_n])

    def value_changed(self, widget, path, text, which_changed):
        """Sets the model to keep the information which the user gave on
        Return Key"""
        active_store = self.current_conflict_model
        if which_changed == "original":
            active_store[path][1] = text
        elif which_changed == "conflict":
            active_store[path][2] = text

    def create_conflicts_models(self, conflicts):
        """ Creates a list of models, one for each conflict. Each model has
        five columns, as shown in an example with only two rows below:
        | PROPERTY | OBJECT 1 | OBJECT 2 | ROW COLOR | INPUT TYPE |
        -----------------------------------------------------------
        | NAME     |    A     |    B     |  RED      |  STRING    |
        | PORTS    | 5050, 20 | 5050, 20 | WHITE     |  LIST      |
        ===========================================================
        ROW COLOR and INPUT TYPE are never shown to the user.
        """

        models = []
        for conflict in conflicts:
            model = Gtk.ListStore(str, str, str, str, str)
            obj1 = conflict.getFirstObject()
            obj2 = conflict.getSecondObject()
            conflict_type = conflict.getModelObjectType()

            if conflict_type == "Service":
                self.fill_service_conflict_model(model, obj1, obj2)
            elif conflict_type == "Interface":
                self.fill_interface_conflict_model(model, obj1, obj2)
            elif conflict_type == "Host":
                self.fill_host_conflict_model(model, obj1, obj2)
            elif conflict_type == "Vulnerability":
                self.fill_vuln_conflict_model(model, obj1, obj2)
            elif conflict_type == "VulnerabilityWeb":
                self.fill_webvuln_conflict_model(model, obj1, obj2)

            models.append(model)

        return models

    def fill_service_conflict_model(self, model, obj1, obj2):
        """
        Precondition: the model has 5 string columns, obj1 && obj2 are services
        Will get a model and two objects and return a
        model with all the appropiate information"""
        attr = []
        for obj in [obj1, obj2]:
            attr.append((obj.getName(),
                         obj.getDescription(),
                         obj.getProtocol(),
                         obj.getStatus(),
                         obj.getPorts(),
                         obj.getVersion(),
                         obj.isOwned()))

        props = ["Name", "Description", "Protocol", "Status", "Ports",
                 "Version", "Owned"]

        model = self.fill_model_from_props_and_attr(model, attr, props)
        return model

    def fill_host_conflict_model(self, model, obj1, obj2):
        """
        Precondition: the model has 5 string columns, obj1 && obj2 are hosts
        Will get a model and two objects and return a
        model with all the appropiate information"""
        attr = []
        for obj in [obj1, obj2]:
            attr.append((obj.getName(),
                         obj.getDescription(),
                         obj.getOS(),
                         obj.isOwned()))

        props = ["Name", "Description", "OS", "Owned"]
        model = self.fill_model_from_props_and_attr(model, attr, props)
        return model

    def fill_interface_conflict_model(self, model, obj1, obj2):
        """
        Precondition: the model has 5 string columns, obj1 && obj2 are
        interfaces
        Will get a model and two objects and return a
        model with all the appropiate information"""
        attr = []
        for obj in [obj1, obj2]:
            attr.append((obj.getName(),
                         obj.getDescription(),
                         obj.getHostnames(),
                         obj.getMAC(),
                         obj.getIPv4Address(),
                         obj.getIPv4Mask(),
                         obj.getIPv4Gateway(),
                         obj.getIPv4DNS(),
                         obj.getIPv6Address(),
                         obj.getIPv6Gateway(),
                         obj.getIPv6DNS(),
                         obj.isOwned()))

        props = ["Name", "Description", "Hostnames", "MAC", "IPv4 Address",
                 "IPv4 Mask", "IPv4 Gateway", "IPv4 DNS", "IPv6 Address",
                 "IPv6 Gateway", "IPv6 DNS", "Owned"]

        model = self.fill_model_from_props_and_attr(model, attr, props)
        return model

    def fill_vuln_conflict_model(self, model, obj1, obj2):
        """
        Precondition: the model has 5 string columns, obj1 && obj2 are vulns
        Will get a model and two objects and return a
        model with all the appropiate information"""
        attr = []
        for obj in [obj1, obj2]:
            attr.append((obj.getName(),
                         obj.getDescription(),
                         obj.getData(),
                         obj.getSeverity(),
                         obj.getRefs()))

        props = ["Name", "Desc", "Data", "Severity", "Refs"]
        model = self.fill_model_from_props_and_attr(model, attr, props)
        return model

    def fill_webvuln_conflict_model(self, model, obj1, obj2):
        """
        Precondition: the model has 5 string columns, obj1 && obj2 are web vuln
        Will get a model and two objects and return a
        model with all the appropiate information"""
        attr = []
        for obj in [obj1, obj2]:
            attr.append((obj.getName(),
                         obj.getDescription(),
                         obj.getData(),
                         obj.getSeverity(),
                         obj.getRefs(),
                         obj.getPath(),
                         obj.getWebsite(),
                         obj.getRequest(),
                         obj.getResponse(),
                         obj.getMethod(),
                         obj.getPname(),
                         obj.getParams(),
                         obj.getQuery(),
                         obj.getCategory()))

        props = ["Name", "Desc", "Data", "Severity", "Refs", "Path",
                 "Website", "Request", "Response", "Method", "Pname",
                 "Params", "Query", "Category"]

        model = self.fill_model_from_props_and_attr(model, attr, props)
        return model

    def fill_model_from_props_and_attr(self, model, attr, props):
        """Preconditions: the model has 5 string columns,
        len(attr[0]) == len(attr[1]) == len(props),
        type(attr[0][i]) == type(attr[1][i]) for every i
        attr is a list with two tuples. the first tuple holds info about obj1,
        the second about obj2, for example:
        [(name_obj1, ports_obj1), (name_obj2, porst_obj2)]
        props is the list with names of such attributes, for example:
        ["Name: ", "Ports: "]

        Will return a model filled up with information as detailed in
        self.create_conflicts_models.
        """

        def decide_type(raw_prop):
            """Returns the name of a type of an object.
            Keep in mind, type(type("a")) is Type,
                          type(type("a").__name__) is Str
            """
            res = type(first_raw_prop).__name__
            return res

        def decide_bg():
            """Decides which background should the row have depending on
            the uses default theme (light, dark, or unknown abomination)
            Pretty ugly, but it works"""
            color = self.bg_color.split("(")[1]
            color = color.split(",")
            color1 = int(color[0])
            color2 = int(color[1])
            color3 = int(color[2][:-1:])

            # that weird string formats from rgb to hexa
            default_bg = '#%02x%02x%02x' % (color1, color2, color3)

            if color1 > 200 and color2 > 200 and color3 > 200:
                return "pink" if first_prop != sec_prop else default_bg
            elif color1 < 100 and color2 < 100 and color3 < 100:
                return "darkred" if first_prop != sec_prop else default_bg
            else:
                # if your theme doesn't go for either dark or light
                # just use that color, screw highlights
                return '#%02x%02x%02x' % (color1, color2, color3)

        for index, prop in enumerate(props):
            # remember props is a list like [(obj1_prop1, obj1_prop2...),
            #                                (obj2_prop1, obj2, prop2...)]
            first_raw_prop = attr[0][index]
            sec_raw_prop = attr[1][index]
            first_prop = self.cook(first_raw_prop)
            sec_prop = self.cook(sec_raw_prop)

            model.append([prop, first_prop, sec_prop,
                          decide_bg(),
                          decide_type(first_raw_prop)])

        return model

    def cook(self, raw_prop):
        """We need to cook our properties: not all of them are strings by
        default, and Gtk's models refuse to deal with lists or dictionaries.
        Returns a string from a list, a bool, a float, or a string.
        DO NOT use for dictionaries"""

        if type(raw_prop) is list:
            cooked_prop = ",".join([str(p) for p in raw_prop])

        elif type(raw_prop) is bool:
            cooked_prop = str(raw_prop)

        elif type(raw_prop) is int or type(raw_prop) is float:
            cooked_prop = str(raw_prop)

        else:
            cooked_prop = raw_prop

        return cooked_prop

    def uncook(self, prop, original_type):
        """We need to get our raw information again: Gtk may like strings,
        but Faraday needs lists, booleans, floats, and such.
        Do not try to use for dictionaries.
        """

        if original_type == "list" or original_type == "NoneType":
            if prop:
                prop = prop.replace(" ", "")
                raw_prop = prop.split(",")
            else:
                raw_prop = []

        elif original_type == "bool":
            prop = prop.replace(" ", "")
            if prop.lower() == "true":
                raw_prop = True
            elif prop.lower() == "false":
                raw_prop = False

        elif original_type == "int":
            raw_prop = int(prop)

        elif original_type == "float":
            raw_prop = float(prop)

        elif original_type == "str" or original_type == "unicode":
            raw_prop = prop

        else:
            raw_prop = prop

        return raw_prop


class NotificationsDialog(Gtk.Window):
    """Defines a simple notification dialog. It isn't much, really"""

    def __init__(self, view, callback, parent):
        Gtk.Window.__init__(self, title="Notifications")
        self.set_type_hint(Gdk.WindowTypeHint.DIALOG)
        self.set_transient_for(parent)
        self.set_size_request(400, 200)
        self.set_modal(True)
        self.connect("key_press_event", key_reactions)
        self.destroy_notifications = callback

        scrolled_list = self.create_view_box(view)

        self.button = Gtk.Button()
        self.button.set_label("OK")
        self.button.connect("clicked", self.on_click_ok)

        self.mainBox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.mainBox.pack_start(scrolled_list, True, True, 0)
        self.mainBox.pack_start(self.button, False, False, 0)

        self.add(self.mainBox)

    @scrollable(width=250, height=350)
    def create_view_box(self, view):
        return view

    def on_click_ok(self, button=None):
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


class ImportantErrorDialog(Gtk.Dialog):
    """Blueprints for an uncaught exception handler. Presents the
    traceback and has option to send error report to developers.
    """

    def __init__(self, parent_window, error):
        Gtk.Dialog.__init__(self, "Error!", parent_window, 0)
        self.add_button("Send report to developers...", 42)
        self.add_button("Ignore", 0)
        self.set_size_request(200, 200)

        textBuffer = Gtk.TextBuffer()
        textBuffer.set_text(error)

        text_view_box = self.create_text_view_box(textBuffer)

        content = self.get_content_area()

        content.pack_start(text_view_box, True, True, 0)
        self.show_all()

    @scrollable(width=200, height=200)
    def create_text_view_box(self, textBuffer):
        textView = Gtk.TextView()
        textView.set_editable(False)
        textView.set_buffer(textBuffer)
        return textView


def key_reactions(window, event):
    """Silly function to destroy a window on escape key, to use
    with all the dialogs that should be Gtk.Dialogs but are Gtk.Windows
    or with windows that are too complex for gtk dialogs but should behave
    as a dialog too"""
    key = Gdk.keyval_name(event.get_keyval()[1])
    if key == 'Escape':
        window.destroy()
        return True
    elif key == 'Return':
        window.on_click_ok()
        return True
