'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import qt
import hostsbrowser as DetailsWidgets
import model.guiapi as guiapi

class BaseForm(qt.QVBox):
    def __init__(self, parent, rows, callback=None):
        qt.QVBox.__init__(self, parent)
        details_label = qt.QLabel("Details", self)
        details_label.setMargin(2)
        self._details_table = DetailsWidgets.DetailsTable(self, editable=True, rows=rows)
        self._widgets = {}
        
        self._callback = callback
        
        self._save_button = qt.QPushButton("Save", self)
        self._save_button.setMaximumWidth(50)
        self.connect(self._save_button, qt.SIGNAL('clicked()'), self._save_object)
    
    def createWidget(self, name, description, info):
        w = self._details_table.setInputWidget(name, description, info)
        self._appendWidget(name, w)
        
    def getWidgetValue(self, name):
        w = self._getWidget(name)
        return w.getValue()
    
    def _appendWidget(self, name, widget):
        self._widgets[name] = widget
    
    def _getWidget(self, name):
        return self._widgets[name]
        
    def _save_object(self):
                                              
        pass
    
    def execCallback(self, name):
        if self._callback is not None:
            self._callback(name)

class ServiceForm(BaseForm):
    def __init__(self, parent, service, callback):
        self.service = service
        BaseForm.__init__(self, parent, 7, callback)
                                                                           
        self.createWidget("description_edit", "Description", self.service.getDescription())
        self.createWidget("name_edit", "Name", self.service.getName())
        self.createWidget("protocol_edit", "Protocol", self.service.getProtocol())
        self.createWidget("ports_edit", "Ports", self.service.getPorts())
        self.createWidget("status_edit", "Status", self.service.getStatus())
        self.createWidget("version_edit", "Version", self.service.getVersion())
        self.createWidget("owned_edit", "Owned", self.service.isOwned())
    
    def _save_object(self):
                                                   
        guiapi.editService(self.service, self.getWidgetValue("name_edit"), self.getWidgetValue("description_edit"),
                        self.getWidgetValue("protocol_edit"), self.getWidgetValue("ports_edit"),
                        self.getWidgetValue("status_edit"), self.getWidgetValue("version_edit"),
                        self.getWidgetValue("owned_edit"))
        name = self.getWidgetValue("name_edit")
        self.execCallback(name)

class ApplicationForm(BaseForm):
    def __init__(self, parent, app, callback):
        self.app = app
        BaseForm.__init__(self, parent, 5, callback)
                                                                           
        self.createWidget("description_edit", "Description", self.app.getDescription())
        self.createWidget("name_edit", "Name", self.app.getName())
        self.createWidget("status_edit", "Status", self.app.getStatus())
        self.createWidget("version_edit", "Version", self.app.getVersion())
        self.createWidget("owned_edit", "Owned", self.app.isOwned())
    
    def _save_object(self):
                                                   
        guiapi.editApplication(self.app, self.getWidgetValue("name_edit"), self.getWidgetValue("description_edit"),
                        self.getWidgetValue("status_edit"), self.getWidgetValue("version_edit"),
                        self.getWidgetValue("owned_edit"))
        name = self.getWidgetValue("name_edit")
        self.execCallback(name)

class InterfaceForm(BaseForm):
    def __init__(self, parent, interface, callback):
        self.interface = interface
        BaseForm.__init__(self, parent, 9, callback)
                                                                           
        self.createWidget("description_edit", "Description", self.interface.getDescription())
        self.createWidget("name_edit", "Name", self.interface.getName())
        self.createWidget("hostnames_edit", "Hostnames", self.interface.getHostnames())
        self.createWidget("mac_edit", "MAC", self.interface.mac)
        self.createWidget("ipv4_edit", "IPv4", self.interface.ipv4)
        self.createWidget("network_segment_edit", "Network Segment", self.interface.network_segment)
        self.createWidget("amount_ports_opened_edit", "Ports opened", self.interface.amount_ports_opened)
        self.createWidget("amount_ports_closed_edit", "Ports closed", self.interface.amount_ports_closed)
        self.createWidget("amount_ports_filtered_edit", "Ports filtered", self.interface.amount_ports_filtered)
        self.createWidget("owned_edit", "Owned", self.interface.isOwned())
    
    def _save_object(self):
                                                   
        guiapi.editInterface(self.interface, self.getWidgetValue("name_edit"), self.getWidgetValue("description_edit"),
                        self.getWidgetValue("hostnames_edit"), self.getWidgetValue("mac_edit"),
                        self.getWidgetValue("ipv4_edit"), self.getWidgetValue("network_segment_edit"),
                        self.getWidgetValue("amount_ports_opened_edit"), self.getWidgetValue("amount_ports_closed_edit"),
                        self.getWidgetValue("amount_ports_filtered_edit"), self.getWidgetValue("owned_edit"))
        name = self.getWidgetValue("name_edit")
        self.execCallback(name)

class HostForm(BaseForm):
    def __init__(self, parent, host, callback):
        self.host = host
        BaseForm.__init__(self, parent, 4, callback)
                                                                           
        self.createWidget("description_edit", "Description", self.host.getDescription())
        self.createWidget("name_edit", "Name", self.host.getName())
        self.createWidget("os_edit", "OS", self.host.getOS())
        self.createWidget("owned_edit", "Owned", self.host.isOwned())
    
    def _save_object(self):
                                                   
        guiapi.editHost(self.host, self.getWidgetValue("name_edit"), self.getWidgetValue("description_edit"),
                        self.getWidgetValue("os_edit"), self.getWidgetValue("owned_edit"))
        name = self.getWidgetValue("name_edit")
        self.execCallback(name)
