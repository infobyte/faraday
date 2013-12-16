'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import qt
import qttable
import model.guiapi as guiapi


class NewModelObjectDialog(qt.QDialog):

    def __init__(self, parent, name, callback, layout_margin=0, layout_spacing=-1, modal=True):
        qt.QDialog.__init__(self, parent, name, modal)
        self.widgets = {}
        self.result = None
        self.callback = callback

        if layout_spacing == -1:
            layout_spacing =  self.fontMetrics().height()

        self.main_layout = qt.QVBoxLayout(self, layout_margin, layout_spacing, "main_layout")
        
        self.setEdition()

        self.button_box = qt.QHBoxLayout()
        self.accept_button = qt.QPushButton("Accept", self)
        self.accept_button.setMaximumSize(qt.QSize(75, 25))
        self.connect(self.accept_button, qt.SIGNAL('clicked()'), self._accept)
        self.cancel_button = qt.QPushButton("Cancel", self)
        self.cancel_button.setMaximumSize(qt.QSize(75, 25))
        self.connect(self.cancel_button, qt.SIGNAL('clicked()'), self.cancel)
        self.button_box.addWidget(self.accept_button)
        self.button_box.addWidget(self.cancel_button)

        self.main_layout.addStretch(1)
        self.main_layout.setMargin(5)
        self.main_layout.setSpacing(6)
        self.main_layout.addLayout(self.button_box)

    def getMainLayout(self):
        return self.main_layout

    def setEdition(self):
                                                
        pass

    def _addWidget(self, label, widget):
        hbox = qt.QHBoxLayout()
        hbox.setMargin(5)
        hbox.addWidget(label)
        hbox.addWidget(widget)
        self.main_layout.addLayout(hbox)

    def getWidget(self, name):
        return self.widgets.get(name, None)

    def addTextEdit(self, name, description, label_size=100):
        label = qt.QLabel(None, description, self)
        label.setMinimumSize(qt.QSize(label_size, 1))
        self.widgets[name] = text_edit = TextEditWidget(self, "")
        text_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Minimum))
        self._addWidget(label, text_edit)

    def addIntEdit(self, name, description, minValue, maxValue, label_size=100):
        label = qt.QLabel(None, description, self)
        label.setMinimumSize(qt.QSize(label_size, 1))
        self.widgets[name] = int_edit = IntEditWidget(self, 1, minValue, maxValue)
        int_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Minimum))
        self._addWidget(label, int_edit)

    def addTextBlockEdit(self, name, description, label_size=100):
        label = qt.QLabel(None, description, self)
        label.setMinimumSize(qt.QSize(label_size, 1))
        label.setAlignment(qt.Qt.AlignTop)
        self.widgets[name] = text_block_edit = TextBlockEditWidget(self, "")
        text_block_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self._addWidget(label, text_block_edit)

    def addComboBox(self, name, description, values, label_size=100):
        label = qt.QLabel(None, description, self)
        label.setMinimumSize(qt.QSize(label_size, 1))
        label.setAlignment(qt.Qt.AlignTop)
        self.widgets[name] = combo_edit = ComboBoxEditWidget(self, values)
        combo_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self._addWidget(label, combo_edit)

    def addCheckBox(self, name, description, callback=None, label_size=100):
        label = qt.QLabel(None, description, self)
        label.setMinimumSize(qt.QSize(label_size, 1))
        label.setAlignment(qt.Qt.AlignTop)
        self.widgets[name] = checkbox_edit = BooleanEditWidget(self, False)
        checkbox_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        if callback:
            self.connect(checkbox_edit, qt.SIGNAL("stateChanged(int)"), callback)
        self._addWidget(label, checkbox_edit)

    def getValues(self):
                                                
        pass

    def getValue(self, name):
        return self.widgets[name].getValue()

    def getResult(self):
        return self.result
    
    def cancel(self):
        self.reject()

    def _accept(self):
        if self.callback is not None:
            self.result = self.callback(*self.getValues())
        self.accept()

    def sizeHint(self):
                                                                  
        return qt.QSize(300, 100)


class NewHostDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Host", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("name", "Name")
        self.addTextEdit("os", "OS")

    def getValues(self):
        return [self.getValue("name"), self.getValue("os")]

class NewCredDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Cred", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("username", "Username")
        self.addTextEdit("password", "Password")

    def getValues(self):
        return [self.getValue("username"), self.getValue("password")]

class NewInterfaceDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Interface", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("name", "Name")
        self.addTextEdit("ipv4", "IPv4")
        self.addTextEdit("ipv6", "IPv6")

    def getValues(self):
        return [self.getValue("name"), self.getValue("ipv4"), self.getValue("ipv6")]


class NewServiceDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Service", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("name", "Name")
        self.addTextEdit("protocol", "Protocol")
        self.addIntEdit("port", "Port", 1, 65535)

    def getValues(self):
        return [self.getValue("name"), self.getValue("protocol"), self.getValue("port")]

class NewNoteDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Note", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("name", "Name", label_size=50)
        self.addTextBlockEdit("text", "Text", label_size=50)

    def getValues(self):
        return [self.getValue("name"), self.getValue("text")]

    def sizeHint(self):
                                                                  
        return qt.QSize(450, 200)

class NewVulnDialog(NewModelObjectDialog):

    def __init__(self, parent, callback, vuln_web_enabled=False, layout_margin=0, layout_spacing=-1, modal=True):
        self.vuln_web_enabled = vuln_web_enabled
        NewModelObjectDialog.__init__(self, parent, "New Vulnerabilty", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        if not self.vuln_web_enabled:
            self.addCheckBox("vuln_web", "Web Vulnerabilty (only for services)", self._type_changed)
            self.getWidget("vuln_web").setEnabled(False)
        else:
            self.addCheckBox("vuln_web", "Web Vulnerabilty", self._type_changed)
        self.addTextEdit("name", "Name")
        self.addTextEdit("desc", "Description")
        self.addTextEdit("website", "Website")
        self.getWidget("website").setEnabled(False)
        self.addTextEdit("path", "Path")
        self.getWidget("path").setEnabled(False)
    
    def _type_changed(self, type):
        self.getWidget("path").setEnabled(bool(type))
        self.getWidget("website").setEnabled(bool(type))

    def getValues(self):
        values = [self.getValue("vuln_web"), self.getValue("name"), self.getValue("desc")]
        if self.getValue("vuln_web"):
            values.extend([self.getValue("website"), self.getValue("path")])
        return values

    def sizeHint(self):
                                                                  
        return qt.QSize(400, 250)

class NewVulnWebDialog(NewModelObjectDialog):

    def __init__(self, parent, callback,  layout_margin=0, layout_spacing=-1, modal=True):
        NewModelObjectDialog.__init__(self, parent, "New Web Vulnerabilty", callback, layout_margin, layout_spacing, modal)

    def setEdition(self):
        self.addTextEdit("name", "Name")
        self.addTextEdit("desc", "Description")
        self.addTextEdit("website", "Website")
        self.addTextEdit("path", "Path")

    def getValues(self):
        return [self.getValue("name"), self.getValue("desc"), self.getValues("website"), self.getValues("path")]


class DetailLabel(qt.QLabel):
    """
    A lable for ModelObject items details
    This implements mouse move and focus events
    This is to show a darker color when mouse is over detail
    and also to show context menues
    """

    def __init__(self, setting, text, parent):

        qt.QLabel.__init__(self, text, parent)
        self.bgcolor = self.paletteBackgroundColor()
        self.setFocusPolicy(qt.QWidget.StrongFocus)
        self.setMargin(1)

        self.setting    = setting
        self.inmenu     = False
        self.inmouse    = False
        self.infocus    = False

    def _setBg(self):
        """Set the background of the widget according to its state."""

                                                              
        num = 100
        if self.inmenu:
            num += 20
        else:
            if self.inmouse:
                num += 10
            if self.infocus:
                num += 10

        self.setPaletteBackgroundColor(self.bgcolor.dark(num))

    def keyPressEvent(self, event):
                                       

        key = event.key()
                                           
        if key == qt.Qt.Key_Up:
            self.focusNextPrevChild(False)
            self.focusNextPrevChild(False)
        elif key == qt.Qt.Key_Down:
            self.focusNextPrevChild(True)
            self.focusNextPrevChild(True)
        elif key == qt.Qt.Key_Left:
            self.focusNextPrevChild(False)
        elif key == qt.Qt.Key_Right:
            self.focusNextPrevChild(True)
        else:
            event.ignore()

    def enterEvent(self, event):
                            
        qt.QLabel.enterEvent(self, event)
        self.inmouse = True
        self._setBg()

    def leaveEvent(self, event):
                                
        qt.QLabel.leaveEvent(self, event)
        self.inmouse = False
        self._setBg()

    def focusInEvent(self, event):
                          
        qt.QLabel.focusInEvent(self, event)
        self.infocus = True
        self._setBg()

    def focusOutEvent(self, event):
                           
        qt.QLabel.focusOutEvent(self, event)
        self.infocus = False
        self._setBg()


class TextEditWidget(qt.QLineEdit):
    def __init__(self, parent, text):
        qt.QLineEdit.__init__(self, parent)
        self._setText(text)
    
    def getValue(self):
        text = self.text().ascii()
        if text:
            return self.text().ascii()
        return ""

    def _setText(self, text):
        text = text if text else ""
        self.setText(text)

class TextBlockEditWidget(qt.QTextEdit):
    def __init__(self, parent, text):
        qt.QTextEdit.__init__(self, parent)
        self._setText(text)
    
    def getValue(self):
        text = self.text().ascii()
        if text:
            return self.text().ascii()
        return ""

    def _setText(self, text):
        text = text if text else ""
        self.setText(text)

class BooleanEditWidget(qt.QCheckBox):
    def __init__(self, parent, value):
        qt.QCheckBox.__init__(self, parent)
        value = value if value else False
        self.setChecked(value)
    
    def getValue(self):
        return self.isChecked()


class IntEditWidget(qt.QSpinBox):
    def __init__(self, parent, value, minValue, maxValue, step=1):
        qt.QSpinBox.__init__(self, parent)
        value = value if value else minValue
        self.setMinValue(minValue)
        self.setMaxValue(maxValue)
        self.setLineStep(step)
        self.setValue(value)
        
    def getValue(self):
        return self.value()

class ComboBoxEditWidget(qt.QComboBox):
    def __init__(self, parent, values):
        qt.QComboBox.__init__(self, 0, parent)
                                      
        for value in values:
            self.insertItem(value)

    def getValue(self):
        return self.currentText()


class ListEditWidget(qt.QHBox):
    def __init__(self, parent, values, title="", preview_size=25):
        qt.QHBox.__init__(self, parent)
        self.title = title
        self.values = values
        self.preview_size = preview_size
        preview = self.getPreview()
        self.list_label = DetailLabel(None, preview, self)
        button = qt.QPushButton("...", self)
        button.setMaximumSize(qt.QSize(25, 25))
        self.connect(button, qt.SIGNAL('clicked()'), self.showListEditor)

    def getValue(self):
        return self.values

    def setValues(self, values):
        self.values = values
        self.updatePreview()

    def getPreview(self):
        return ", ".join(["%s" % hn for hn in self.values])[0:25]

    def updatePreview(self):
        self.list_label.setText(self.getPreview())

    def showListEditor(self):
        dialog = ListEditDialog(self, self.title, self.values)
        result = dialog.exec_loop()
        self.values = dialog.getValues()
        self.updatePreview()


class ListEditDialog(qt.QDialog):

    def __init__(self, parent, name, values, layout_margin=0, layout_spacing=-1, modal=True):
        qt.QDialog.__init__(self, parent, name, modal)
        if layout_spacing == -1:
            layout_spacing =  self.fontMetrics().height()

        self.list_layout = qt.QVBoxLayout()
        self.listview = qt.QListView(self)
        self.listview.setSelectionMode(qt.QListView.Extended)
        self.listview.addColumn(name)
        self.listview.setColumnWidthMode(0, qt.QListView.Maximum)
        for value in values:
            view_item = qt.QListViewItem(self.listview)
            view_item.setText(0, qt.QString(value))

        self.list_layout.addWidget(self.listview)

        self.button_box = qt.QVBoxLayout()
        self.add_button = qt.QPushButton("Add", self)
        self.add_button.setMaximumSize(qt.QSize(100, 100))
        self.connect(self.add_button, qt.SIGNAL('clicked()'), self.addValue)
        self.remove_button = qt.QPushButton("Remove", self)
        self.remove_button.setMaximumSize(qt.QSize(100, 100))
        self.connect(self.remove_button, qt.SIGNAL('clicked()'), self.removeValue)
        self.close_button = qt.QPushButton("Close", self)
        self.close_button.setMaximumSize(qt.QSize(100, 100))
        self.connect(self.close_button, qt.SIGNAL('clicked()'), self.close)
        self.button_box.addWidget(self.add_button)
        self.button_box.addWidget(self.remove_button)
        self.button_box.addStretch(2)
        self.button_box.addWidget(self.close_button)

        self.main_layout = qt.QHBoxLayout(self, layout_margin, layout_spacing, "main_layout")
        self.main_layout.addLayout(self.list_layout)
        self.main_layout.addLayout(self.button_box)

    def getValues(self):
        values = []
        iter = qt.QListViewItemIterator(self.listview)
        while True:
            item = iter.current()
            if item == None:
                break
            values.append(item.text(0).ascii())
            iter += 1
        return values

    def addValue(self):
        text, ok = qt.QInputDialog.getText('New value', 'New value:')
        if not ok or text == '':
            return
        view_item = qt.QListViewItem(self.listview)
        view_item.setText(0, qt.QString(text))

    def removeValue(self):
        items_selected = []
        iter = qt.QListViewItemIterator(self.listview)
        while True:
            item = iter.current()
            if item == None:
                break
            if item.isSelected():
                items_selected.append(item)
            iter += 1
        for item in items_selected:
            self.listview.takeItem(item)
            del item

    def close(self):
        self.accept()

    def sizeHint(self):
                                                                  
        return qt.QSize(400, 400)


class EditionTable(qttable.QTable):
    """The table which shows the details of item selected on the tree"""

    def __init__(self, parent, rows = 0, columns = 2):
        qttable.QTable.__init__(self, parent)
        self.setFocusPolicy(qt.QWidget.NoFocus)
                                                      
        self.setNumCols(columns)
        self.setNumRows(rows)
        self.setTopMargin(0)
        self.setLeftMargin(0)
        self.setShowGrid(False)
        self.setColumnStretchable(1, True)
        self.setSelectionMode(qttable.QTable.NoSelection)
        
        self._row_count = 0
                          

    def setEditable(self, editable):
        self._editable = editable
    
    def isEditable(self):
        return self._editable

    def _addWidget(self, label, widget):
        self.setCellWidget(self._row_count, 0, label)
        self.setCellWidget(self._row_count, 1, widget)
                                    
        self._row_count += 1

    def addTextEdit(self, description, value):
        view = self.viewport()
        label = DetailLabel(None, description, view)
        textEdit = TextEditWidget(view, value)
        self._addWidget(label, textEdit)
        return textEdit

    def addBooleanEdit(self, description, value):
        view = self.viewport()
        label = DetailLabel(None, description, view)
        booleanEdit = BooleanEditWidget(view, value)
        self._addWidget(label, booleanEdit)
        return booleanEdit    

    def addIntEdit(self, description, value, minValue, maxValue):
        view = self.viewport()
        label = DetailLabel(None, description, view)
        intEdit = IntEditWidget(view, value, minValue, maxValue)
        self._addWidget(label, intEdit)  
        return intEdit

    def addListEdit(self, description, values, title):
        view = self.viewport()
        label = DetailLabel(None, description, view)
        listEdit = ListEditWidget(view, values, title)
        self._addWidget(label, listEdit)  
        return listEdit

    def clear(self):
        self._row_count = 0
        self.setNumRows(0)
                             
    
    def keyPressEvent(self, event):
        """This method is necessary as the table steals keyboard input
        even if it cannot have focus."""
        fw = self.focusWidget()
        if fw != self:
            try:
                fw.keyPressEvent(event)
            except RuntimeError:
                                                                     
                event.ignore()
        else:
            event.ignore()

    def keyReleaseEvent(self, event):
        """This method is necessary as the table steals keyboard input
        even if it cannot have focus."""
        fw = self.focusWidget()
        if fw != self:
            try:
                fw.keyReleaseEvent(event)
            except RuntimeError:
                                                                     
                event.ignore()
        else:
            event.ignore()

class HostEditor():
    def __init__(self, host):
        self.host = host
        self.widgets = {}

    def getArgs(self):
        return {
            "name" : self.widgets["name"].getValue(),
            "description" : self.widgets["description"].getValue(),
            "os" : self.widgets["os"].getValue(),
            "owned" : self.widgets["owned"].getValue(),
        }

    def save(self):
        kargs = self.getArgs()
        if kargs["name"]:
            guiapi.editHost(self.host, **kargs)
            return True
        return False

    def fillEditionTable(self, qttable):
        qttable.clear()
        qttable.setNumRows(4)
        self.widgets["name"] = qttable.addTextEdit("Name", self.host.getName())
        self.widgets["description"] = qttable.addTextEdit("Description", self.host.getDescription())
        self.widgets["os"] = qttable.addTextEdit("OS", self.host.getOS())
        self.widgets["owned"] = qttable.addBooleanEdit("Owned", self.host.isOwned())

class InterfaceEditor():
    def __init__(self, interface):
        self.interface = interface
        self.widgets = {}

    def getArgs(self):
        return {
            "name" : self.widgets["name"].getValue(),
            "description" : self.widgets["description"].getValue(),
            "mac" : self.widgets["mac"].getValue(),
            "ipv4" : {
                'address' : self.widgets["ipv4_address"].getValue(),
                'mask' : self.widgets["ipv4_mask"].getValue(),
                'gateway' : self.widgets["ipv4_gateway"].getValue(),
                'DNS' : self.widgets["ipv4_dns"].getValue()
            },
            "ipv6" : {
                'address' : self.widgets["ipv6_address"].getValue(),
                'prefix' : self.widgets["ipv6_prefix"].getValue(),
                'gateway' : self.widgets["ipv6_gateway"].getValue(),
                'DNS' : self.widgets["ipv6_dns"].getValue(),    
            },
            "owned" : self.widgets["owned"].getValue(),
            "hostnames" : self.widgets["hostanmes"].getValue()
        }

    def save(self):
        kargs = self.getArgs()
        if kargs["name"]:
            guiapi.editInterface(self.interface, **kargs)
            return True
        return False

    def fillEditionTable(self, qttable):
        qttable.clear()
        qttable.setNumRows(11)
        self.widgets["name"] = qttable.addTextEdit("Name", self.interface.getName())
        self.widgets["description"] = qttable.addTextEdit("Description", self.interface.getDescription())
        self.widgets["mac"] = qttable.addTextEdit("MAC", self.interface.getMAC())
        self.widgets["hostanmes"] = qttable.addListEdit("Hostnames", self.interface.getHostnames(), "Hostnames")
        self.widgets["ipv4_address"] = qttable.addTextEdit("IPv4 Address", self.interface.getIPv4Address())
        self.widgets["ipv4_mask"] = qttable.addTextEdit("IPv4 Mask", self.interface.getIPv4Mask())
        self.widgets["ipv4_gateway"] = qttable.addTextEdit("IPv4 Gateway", self.interface.getIPv4Gateway())
        self.widgets["ipv4_dns"] = qttable.addListEdit("IPv4 DNS", self.interface.getIPv4DNS(), "IPv4 DNS")
        self.widgets["ipv6_address"] = qttable.addTextEdit("IPv6 Address", self.interface.getIPv6Address())
        self.widgets["ipv6_prefix"] = qttable.addTextEdit("IPv6 Prefix", self.interface.getIPv6Prefix())
        self.widgets["ipv6_gateway"] = qttable.addTextEdit("IPv6 Gateway", self.interface.getIPv6Gateway())
        self.widgets["ipv6_dns"] = qttable.addListEdit("IPv6 DNS", self.interface.getIPv6DNS(), "IPv6 DNS")
        self.widgets["owned"] = qttable.addBooleanEdit("Owned", self.interface.isOwned())

class ServiceEditor():
    def __init__(self, service):
        self.service = service
        self.widgets = {}

    def getArgs(self):
        return {
            "name" : self.widgets["name"].getValue(),
            "description" : self.widgets["description"].getValue(),
            "protocol" : self.widgets["protocol"].getValue(),
            "ports" : self.widgets["port"].getValue(),
            "status" : self.widgets["status"].getValue(),
            "version" : self.widgets["version"].getValue(),
            "owned" : self.widgets["owned"].getValue()
        }
    
    def save(self):
        kargs = self.getArgs()
        if kargs["name"] and kargs["protocol"] and kargs["ports"]:
            guiapi.editService(self.service, **kargs)
            return True
        return False

    def fillEditionTable(self, qttable):
        qttable.clear()
        qttable.setNumRows(7)
        self.widgets["name"] = qttable.addTextEdit("Name", self.service.getName())
        self.widgets["description"] = qttable.addTextEdit("Description", self.service.getDescription())
        self.widgets["protocol"] = qttable.addTextEdit("Protocol", self.service.getProtocol())
                                                                                                  
                                             
        self.widgets["port"] = qttable.addIntEdit("Port", self.service.getPorts()[0], 1, 65535)
        self.widgets["status"] = qttable.addTextEdit("Status", self.service.getStatus())
        self.widgets["version"] = qttable.addTextEdit("Version", self.service.getVersion())
        self.widgets["owned"] = qttable.addBooleanEdit("Owned", self.service.isOwned())


class GenericEditor():
    def __init__(self, object):
        pass

    def save(self):
        pass

    def fillEditionTable(self, qttable):
        pass

class NoteEditor(qt.QVBoxLayout):
    def __init__(self, parent):
        qt.QVBoxLayout.__init__(self)
        self.note = None

        self.setSpacing(10)

        label = qt.QLabel(None, "Name: ", parent)
        self._name_edit = TextEditWidget(parent, "")
        self._name_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._name_edit)
        label = qt.QLabel(None, "Text: ", parent)
        self._text_edit = TextBlockEditWidget(parent, "")
        self._text_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self.addWidget(label)
        self.addWidget(self._text_edit)

    def setNote(self, note):
        self.note = note
        self._name_edit._setText(note.name)
        self._text_edit._setText(note.text)

    def clear(self):
        self.note = None
        self._name_edit._setText("")
        self._text_edit._setText("")

    def getArgs(self):
        return {
            "name" : self._name_edit.getValue(),
            "text" : self._text_edit.getValue()
        }

class VulnEditor(qt.QVBoxLayout):
    def __init__(self, parent):
        qt.QVBoxLayout.__init__(self, parent)
        self.vuln = None

        self.setSpacing(10)

        label = qt.QLabel(None, "Name: ", parent)
        self._name_edit = TextEditWidget(parent, "")
        self._name_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._name_edit)
        label = qt.QLabel(None, "Description: ", parent)
        self._description_edit = TextBlockEditWidget(parent, "")
        self._description_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self.addWidget(label)
        self.addWidget(self._description_edit)
        label = qt.QLabel(None, "Severity: ", parent)
        self._severity_edit = TextEditWidget(parent, "")
        self._severity_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._severity_edit)
        label = qt.QLabel(None, "References: ", parent, "References")
        self._references_edit = ListEditWidget(parent, [], preview_size=100)
        self.addWidget(label)
        self.addWidget(self._references_edit)


    def setVuln(self, vuln):
        self.vuln = vuln
        self._name_edit._setText(vuln.name)
        self._description_edit._setText(vuln.desc)
        self._severity_edit._setText(vuln.severity)
        self._references_edit.setValues(vuln.refs)

    def clear(self):
        self.vuln = None
        self._name_edit._setText("")
        self._description_edit._setText("")
        self._severity_edit._setText("")
        self._references_edit.setValues([])

    def getArgs(self):
        return {
            "name" : self._name_edit.getValue(),
            "desc" : self._description_edit.getValue(),
            "severity" : self._severity_edit.getValue(),
            "refs" : self._references_edit.getValue()
        }

class VulnWebEditor(VulnEditor):
    def __init__(self, parent):
        VulnEditor.__init__(self, parent)
        self.vuln = None

        self.setSpacing(10)

        label = qt.QLabel(None, "Path: ", parent)
        self._path_edit = TextEditWidget(parent, "")
        self._path_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._path_edit)

        label = qt.QLabel(None, "Website: ", parent)
        self._website_edit = TextEditWidget(parent, "")
        self._website_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._website_edit)

        label = qt.QLabel(None, "Request: ", parent)
        self._request_edit = TextBlockEditWidget(parent, "")
        self._request_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self.addWidget(label)
        self.addWidget(self._request_edit)

        label = qt.QLabel(None, "Response: ", parent)
        self._response_edit = TextBlockEditWidget(parent, "")
        self._response_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
        self.addWidget(label)
        self.addWidget(self._response_edit)

        label = qt.QLabel(None, "Method: ", parent)
        self._method_edit = TextEditWidget(parent, "")
        self._method_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._method_edit)

        label = qt.QLabel(None, "Parameter Name: ", parent)
        self._pname_edit = TextEditWidget(parent, "")
        self._pname_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._pname_edit)

        label = qt.QLabel(None, "Parameters: ", parent)
        self._params_edit = TextEditWidget(parent, "")
        self._params_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._params_edit)

        label = qt.QLabel(None, "Query: ", parent)
        self._query_edit = TextEditWidget(parent, "")
        self._query_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._query_edit)

        label = qt.QLabel(None, "Category: ", parent)
        self._category_edit = TextEditWidget(parent, "")
        self._category_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Minimum, qt.QSizePolicy.Minimum))
        self.addWidget(label)
        self.addWidget(self._category_edit)

    def setVuln(self, vuln):
        super(VulnWebEditor, self).setVuln(vuln)
        self._path_edit._setText(vuln.path)
        self._website_edit._setText(vuln.website)
        self._request_edit._setText(vuln.request)
        self._response_edit._setText(vuln.response)
        self._method_edit._setText(vuln.method)
        self._pname_edit._setText(vuln.pname)
        self._params_edit._setText(vuln.params)
        self._query_edit._setText(vuln.query)
        self._category_edit._setText(vuln.category)

    def clear(self):
        super(VulnWebEditor, self).clear()
        self._name_edit._setText("")
        self._path_edit._setText("")
        self._website_edit._setText("")
        self._request_edit._setText("")
        self._response_edit._setText("")
        self._method_edit._setText("")
        self._pname_edit._setText("")
        self._params_edit._setText("")
        self._query_edit._setText("")
        self._category_edit._setText("")

    def getArgs(self):
        dic = super(VulnWebEditor, self).getArgs()
        dic.update(
            {
            "path" : self._path_edit.getValue(),
            "website" : self._website_edit.getValue(),
            "request" : self._request_edit.getValue(),
            "response" : self._response_edit.getValue(),
            "method" : self._method_edit.getValue(),
            "pname" : self._pname_edit.getValue(),
            "params" : self._params_edit.getValue(),
            "query" : self._query_edit.getValue(),
            "category" : self._category_edit.getValue()
        })
        return dic

class CredEditor(qt.QVBoxLayout):
    def __init__(self, parent):
        qt.QVBoxLayout.__init__(self)
        self.cred = None

        self.setSpacing(10)

        label = qt.QLabel(None, "Username: ", parent)
        label.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Maximum, qt.QSizePolicy.Maximum))
        self._username_edit = TextEditWidget(parent, "")
        self._username_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Maximum))
        self.addWidget(label)
        self.addWidget(self._username_edit)
        label = qt.QLabel(None, "Password: ", parent)
        label.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Maximum, qt.QSizePolicy.Maximum))
        self._password_edit = TextEditWidget(parent, "")
        self._password_edit.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Maximum))
        self.addWidget(label)
        self.addWidget(self._password_edit)
                                                                                               
        self.addStretch(15)

    def setCred(self, cred):
        self.cred = cred
        self._username_edit._setText(cred.username)
        self._password_edit._setText(cred.password)

    def clear(self):
        self.cred = None
        self._username_edit._setText("")
        self._password_edit._setText("")

    def getArgs(self):
        return {
            "username" : self._username_edit.getValue(),
            "password" : self._password_edit.getValue()
        }
        
