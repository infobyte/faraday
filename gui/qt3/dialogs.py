#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
import qt
import model.api as api
import model.guiapi as guiapi
import re
import model.hosts as hosts
from managers.model_managers import WorkspaceManager
from ui.plugin_settings import *
from ui.vulnerabilities import *
from ui.preferences import *
from ui.noteslist import NotesListUI
from ui.evidenceslist import *
from edition import EditionTable, HostEditor, ServiceEditor, InterfaceEditor, NoteEditor, NewNoteDialog, VulnEditor, NewVulnDialog, VulnWebEditor, NewCredDialog, CredEditor
from modelobjectitems import NoteRootItem, VulnRootItem, CredRootItem

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

                                                                       
                                               
class LogConsole(qt.QVBox):
    """
    widget component used to display a log or any other content in
    a small console window
    """
    tag_regex = re.compile(r"^(\[(.*)\]\s+-).*$", re.DOTALL)
    tag_replace_regex = re.compile(r"^(\[(.*)\]\s+-)")
    tag_colors = {
        "NOTIFICATION" : "#1400F2",
        "INFO" : "#000000",
        "WARNING" : "#F5760F",
        "ERROR" : "#FC0000",
        "CRITICAL": "#FC0000",
        "DEBUG" : "#0AC400",
    }

    def __init__(self, parent, caption=""):
        qt.QVBox.__init__(self, parent)
        self.setName(caption)
        self._text_edit = qt.QTextEdit(self, caption)
                                           
        self._text_edit.setTextFormat(qt.Qt.LogText)

    def customEvent(self, event):
        self.update(event)

    def update(self, event):
        if event.type() == 3131:
            self.appendText(event.text)

    def appendText(self, text):
        """
        appends new text to the console
        """
        m = self.tag_regex.match(text)
        if m is not None:
            tag = m.group(2).upper()
            colored_tag = "<font color=\"%s\"><b>[%s]</b></font> -" % (self.tag_colors.get(tag, "#000000"), tag)
            text = self.tag_replace_regex.sub(colored_tag, text)
        else:
            text = "<font color=\"#000000\"><b>[INFO]</b></font> - %s" % text

        self._text_edit.append(text)

    def clear(self):
        """
        Clear the console
        """
        self._text_edit.clear()

    def sizeHint(self):
        """Returns recommended size of dialog."""
        return qt.QSize(90, 30)

                                                                                

class BaseDialog(qt.QDialog):

    def __init__(self, parent, name, layout_margin=0, layout_spacing=-1, modal=True):
        qt.QDialog.__init__(self, parent, name, modal)
        if layout_spacing == -1:
            layout_spacing =  self.fontMetrics().height()

        self.layout = qt.QVBoxLayout(self, layout_margin, layout_spacing, "layout")
        self.button_box = None
        self.ok_button = None
        self.cancel_button = None
        self.quit_button = None

    def setupButtons(self, buttons=None):
        """
        Creates and setup buttons clicked singal connection using callbacks provided
        The buttons parameter must be a dict with keys (in lowercase)
        "ok", "cancel" or "quit" and a callback reference as value.
        If None is provided as callback value then default behaviour will
        be applied to the button (accept for Ok, reject for cancel and quit)
        Button order will be always Ok, Cancel and Quit
        This will add only the buttons provided in the buttons parameter, so not all
        keys must be used. You can add only the ones needed.
        If no parameter is provided, OK and Cancel buttons will be added with
        their default behaviour.
        IMPORTANT: if callbacks do not call accept or reject methods, then
        the dialog won't end and will be visible. Remember to call accept &
        reject internally on your provided callbacks
        """
        self.button_box = qt.QHBoxLayout(self.layout)
        spacer = qt.QSpacerItem(0,0,qt.QSizePolicy.Expanding,qt.QSizePolicy.Minimum)
        self.button_box.addItem(spacer)

        if buttons is None:
            self._addOkButton()
            self._addCancelButton()
        else:
            if "ok" in buttons:
                self._addOkButton(buttons["ok"])
            if "cancel" in buttons:
                self._addCancelButton(buttons["cancel"])
            if "quit" in buttons:
                self._addQuitButton(buttons["quit"])

    def _addOkButton(self, callback=None):
        self.ok_button = qt.QPushButton( "OK", self )
        self.button_box.addWidget( self.ok_button )
        if callback is None:
            callback = self.accept
        self.connect( self.ok_button, qt.SIGNAL('clicked()'), callback )

    def _addCancelButton(self, callback=None):
        self.cancel_button = qt.QPushButton("Cancel", self)
        self.button_box.addWidget( self.cancel_button )
        if callback is None:
            callback = self.reject
        self.connect( self.cancel_button, qt.SIGNAL('clicked()'), callback)

    def _addQuitButton(self, callback=None):
        self.quit_button = qt.QPushButton("Quit", self)
        self.button_box.addWidget( self.quit_button )
        if callback is None:
            callback = self.reject
        self.connect( self.quit_button, qt.SIGNAL('clicked()'), callback)

    def sizeHint(self):
                                                                  
        return qt.QSize(400, 150)

                                                                                

class LoginDialog(BaseDialog):
    def __init__(self, parent, callback):
        BaseDialog.__init__(self, parent, "Login",
                            layout_margin=10, layout_spacing=15, modal=True)

        self._auth_callback = callback
        self.setCaption("Login")

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        self._username_label = qt.QLabel("Username", hbox1)
        self._username_edit = qt.QLineEdit(hbox1)
        self.layout.addWidget(hbox1)

        hbox2 = qt.QHBox(self)
        hbox2.setSpacing(10)
        self._password_label = qt.QLabel("Password", hbox2)
        self.__password_edit = qt.QLineEdit(hbox2)
        self.__password_edit.setEchoMode(qt.QLineEdit.Password)
        self.layout.addWidget(hbox2)

        self.__username_txt = self._username_edit.text()
        self.__passwd_txt = self.__password_edit.text()

        self.setupButtons({
            "ok" : self._login,
            "cancel" : self._clear,
            "quit" : None,
            })

    def getData(self):
        self.__username_txt = self._username_edit.text()
        self.__passwd_txt = self.__password_edit.text()
        return self.__username_txt.latin1(), self.__passwd_txt.latin1()

    def _login(self):
                                                                 
                               
        self.__username_txt = self._username_edit.text()
        self.__passwd_txt = self.__password_edit.text()
        api.devlog("Username: %s\nPassword: %s" %(self.__username_txt, self.__passwd_txt))
        self.accept()

    def _clear(self):
                                          
        self._username_edit.clear()
        self.__password_edit.clear()

    def sizeHint(self):
        return qt.QSize(250, 100)

                                                                                

class DebugPersistenceDialog(BaseDialog):

    def __init__(self, parent):
        BaseDialog.__init__(self, parent, "PersistenceDebugDialog",
                            layout_margin=15, layout_spacing=10, modal=True)
        self.setCaption( 'Persistence Debug Dialog' )

        self.layout.addWidget( self.logolabel )
        self.layout.addWidget( self.text )
        self.setupButtons({"ok" : None})

                                                                                

class ConflictResolutionDialog(BaseDialog):
    def __init__(self, conflicts, parent=None, name=None):

        BaseDialog.__init__(self, parent, "Conflicts",
                            layout_margin=10, layout_spacing=15, modal=True)

        self.conflict = None
        self.conflict_iterator = iter(conflicts)
        self.first_object = None
        self.second_object = None

        hbox = qt.QHBoxLayout()

        vbox = qt.QVBoxLayout()
        self.label_first_object = qt.QLabel("", self)
        vbox.addWidget(self.label_first_object)
        self.detailtable_first_object = EditionTable(self)
        self.editor_first_object = None
        vbox.addWidget(self.detailtable_first_object)
        self.choice_button_first_object = qt.QRadioButton(self, "")
        vbox.addWidget(self.choice_button_first_object)

        hbox.addLayout(vbox)

        vbox = qt.QVBoxLayout()
        self.label_second_object = qt.QLabel("", self)
        vbox.addWidget(self.label_second_object)
        self.detailtable_second_object = EditionTable(self)
        self.editor_second_object = None
        vbox.addWidget(self.detailtable_second_object)
        self.choice_button_second_object = qt.QRadioButton(self, "")
        vbox.addWidget(self.choice_button_second_object)

        self.object_group_button = qt.QButtonGroup()
        self.object_group_button.insert(self.choice_button_first_object)
        self.object_group_button.insert(self.choice_button_second_object)
        
        hbox.addLayout(vbox)

        self.layout.addLayout(hbox)

        self.setupButtons({"ok": self.resolve, "cancel": self.quit})

        self.del_callback = None
        self.add_callback = None

        self.setup()

    def setup(self):
        self.getNextConflict()
        if self.conflict:
            self.setupConflict()
        else:
            self.accept()

    def getNextConflict(self):
        try:
            self.conflict = self.conflict_iterator.next()
        except StopIteration:
            self.conflict = None

    def setupConflict(self):
        if not self.conflict:
            return

        self.first_object = self.conflict.getFirstObject()
        self.second_object = self.conflict.getSecondObject()
        type = self.conflict.getModelObjectType()
        
        self.setCaption(type)
        name_first_object = self.first_object.getName()
        name_second_object = self.second_object.getName()
        if self.first_object.getParent() is not None:
            name_first_object += " (Host: %s)" % self.first_object.getHost().getName()
            name_second_object += " (Host: %s)" % self.first_object.getHost().getName()
        self.label_first_object.setText(name_first_object)
        self.label_second_object.setText(name_second_object)

        if type == "Host":
            self.editor_first_object = HostEditor(self.first_object)
            self.editor_second_object = HostEditor(self.second_object)
        elif type == "Interface":
            self.editor_first_object = InterfaceEditor(self.first_object)
            self.editor_second_object = InterfaceEditor(self.second_object)
        elif type == "Service":
            self.editor_first_object = ServiceEditor(self.first_object)
            self.editor_second_object = ServiceEditor(self.second_object)

        self.editor_first_object.fillEditionTable(self.detailtable_first_object)
                                               
        self.editor_second_object.fillEditionTable(self.detailtable_second_object)
                                                

    def getSelectedEditor(self):
        if self.choice_button_first_object.isChecked():
            editor = self.editor_first_object
        elif self.choice_button_second_object.isChecked():
            editor = self.editor_second_object
        else:
            editor = None
        return editor

    def resolve(self):
        editor_selected = self.getSelectedEditor()
        if editor_selected:
            guiapi.resolveConflict(self.conflict, editor_selected.getArgs())
        self.setup()

    def quit(self):
        self.reject()

    def sizeHint(self):
        return qt.QSize(750, 500)

                                                                                

class ModelObjectListViewItem(qt.QListViewItem):
    def __init__(self, qtparent, model_object=None):
        qt.QListViewItem.__init__(self, qtparent)
        self.model_object = model_object
        if self.model_object:
            self.setText(0, model_object.name)
        else:
            self.setText(0, "")

    def getModelObject(self):
        return self.model_object

class ListableObjecttDialog(BaseDialog):
    def __init__(self, parent=None, title=None, model_object=None, objects_list = [], layout_margin=10, layout_spacing=15, modal=True):
        BaseDialog.__init__(self, parent, title,
                            layout_margin=10, layout_spacing=15, modal=True)

        hbox = qt.QHBoxLayout()
        vbox1 = qt.QVBoxLayout()
        vbox1.setMargin(5)
        vbox2 = qt.QVBoxLayout()
        vbox2.setMargin(5)
        self.model_object = model_object
        self.objects_list = objects_list
        self._selected_object = None
        self._current_item = None
        self._selected_items = []
        self.edition_layout = None
        self.title = title
        
        self.listview = qt.QListView(self)
        self.listview.setSorting(-1)
        self.listview.setSelectionMode(qt.QListView.Extended)
        self.connect(self.listview, qt.SIGNAL("selectionChanged()"), self._itemSelected)
        self.listview.addColumn(title, self.listview.size().width())
        self.listview.setColumnWidthMode(0, qt.QListView.Maximum)
        self.setListItems()

        vbox1.addWidget(self.listview)
        
        self.button_box1 = qt.QHBoxLayout()
        self.add_button = qt.QPushButton("Add", self)
        self.add_button.setMaximumSize(qt.QSize(100, 25))
        self.connect(self.add_button, qt.SIGNAL('clicked()'), self.addValue)
        self.remove_button = qt.QPushButton("Remove", self)
        self.remove_button.setMaximumSize(qt.QSize(100, 25))
        self.connect(self.remove_button, qt.SIGNAL('clicked()'), self.removeValue)
        self.button_box1.addWidget(self.add_button)
        self.button_box1.addWidget(self.remove_button)
        self.button_box1.addStretch(1)

        vbox1.addLayout(self.button_box1)

        self.setupEditor(vbox2)

        self.button_box2 = qt.QHBoxLayout()
        self.save_button = qt.QPushButton("Save", self)
        self.save_button.setMaximumSize(qt.QSize(100, 25))
        self.connect(self.save_button, qt.SIGNAL('clicked()'), self.saveValue)
        self.button_box2.addWidget(self.save_button)
        self.button_box2.addStretch(1)

        vbox2.addLayout(self.button_box2)
        
        hbox.setSpacing(6)
        hbox.addLayout(vbox1)
        hbox.addLayout(vbox2)
        self.layout.addLayout(hbox)

        self.setupButtons({"quit": None})

    def setupEditor(self, parent_layout):
        pass

    def saveValue(self):
        pass

    def addValue(self):
        pass

    def removeValue(self):
        pass

    def _itemSelected(self):
        self.edition_layout.clear()
        self._current_item = self.listview.currentItem()
        i = self.listview.firstChild()
        self._selected_items=[]
        while i is not None:
            if i.isSelected():
                self._selected_items.append(i)
            i = i.itemBelow()
        self.setEdition()

    def sizeHint(self):
        return qt.QSize(750, 500)

class NotesDialog(ListableObjecttDialog):
    def __init__(self, parent=None, model_object=None):
        ListableObjecttDialog.__init__(self, parent, "Notes", model_object, model_object.getNotes(),
                            layout_margin=10, layout_spacing=15, modal=True)

    def setupEditor(self, parent_layout):
        self.edition_layout = NoteEditor(self)
        parent_layout.addLayout(self.edition_layout)

    def setListItems(self):
        self.listview.clear()
        self.rootitem = NoteRootItem(self.listview, self.title, self.model_object)
        for obj in self.model_object.getNotes():
            self.rootitem.addNote(obj)

    def setEdition(self):
        if self._current_item is not None:
            if self._current_item.type == "Note":
                self.edition_layout.setNote(self._current_item.getModelObject())
        
    def saveValue(self):
        if self._current_item is not None:
            if self._current_item.type == "Note":
                note = self._current_item.getModelObject()
                kwargs = self.edition_layout.getArgs()
                if kwargs["name"] and kwargs["text"]:
                    guiapi.editNote(note, **kwargs)
                    self.setListItems()

    def addValue(self):
        dialog = NewNoteDialog(self, callback=self.__addValue)
        dialog.exec_loop()
    
    def __addValue(self, *args):
        obj = self.rootitem.getModelObject()
        if self._current_item:
            obj = self._current_item.getModelObject()
        guiapi.createAndAddNote(obj, *args)
        self.setListItems()

    def removeValue(self):
        for item in self._selected_items: 
            if item.type == "Note":
                note = item.getModelObject()
                guiapi.delNote(note.getParent().getID(), note.getID())
        self.setListItems()
        self.edition_layout.clear()
                    

    def sizeHint(self):
        return qt.QSize(750, 500)


class VulnsDialog(ListableObjecttDialog):
    def __init__(self, parent=None, model_object=None):
        ListableObjecttDialog.__init__(self, parent, "Vulns", model_object, model_object.getVulns(),
                            layout_margin=10, layout_spacing=15, modal=True)

    def setupEditor(self, parent_layout):
        self._widget_stack = qt.QWidgetStack(self)

        self._vuln_edition_widget = qt.QFrame()
        self._vuln_edition_layout = VulnEditor(self._vuln_edition_widget)
        
        self._vuln_web_scrollbar_view = qt.QScrollView()
        self._vuln_web_scrollbar_view.setResizePolicy(qt.QScrollView.AutoOneFit)
        self._vuln_web_edition_widget = qt.QFrame(self._vuln_web_scrollbar_view.viewport())
        self._vuln_web_edition_layout = VulnWebEditor(self._vuln_web_edition_widget)
        self._vuln_web_edition_layout.setMargin(5)
        self._vuln_web_scrollbar_view.addChild(self._vuln_web_edition_widget)
        
        self._widget_stack.addWidget(self._vuln_edition_widget, 0)
        self._widget_stack.addWidget(self._vuln_web_scrollbar_view, 1)
        self._widget_stack.raiseWidget(self._vuln_edition_widget)
        
        self._vuln_edition_widget.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Ignored, qt.QSizePolicy.Ignored))
        self._vuln_web_edition_widget.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Ignored, qt.QSizePolicy.Ignored))
        
        self.edition_layout = self._vuln_edition_widget.layout()
        
        parent_layout.addWidget(self._widget_stack)

    def setListItems(self):
        self.listview.clear()
        self.rootitem = VulnRootItem(self.listview, self.title, self.model_object)
        for obj in self.model_object.getVulns():
            self.rootitem.addVuln(obj)

    def setEdition(self):
        if self._current_item is not None:
            if self._current_item.type == "Vuln" or self._current_item.type == "VulnWeb":
                widget = self._vuln_edition_widget
                self._widget_stack.raiseWidget(widget)
                if self._current_item.type == "VulnWeb":
                    widget = self._vuln_web_edition_widget
                    self._widget_stack.raiseWidget(self._vuln_web_scrollbar_view)
                self.edition_layout = widget.layout()
                self.edition_layout.setVuln(self._current_item.getModelObject())
        
    def saveValue(self):
        if self._current_item is not None:
            if self._current_item.type == "Vuln" or self._current_item.type == "VulnWeb":
                vuln = self._current_item.getModelObject()
                kwargs = self.edition_layout.getArgs()
                if kwargs["name"] and kwargs["desc"]:
                    if self._current_item.type == "Vuln":
                        guiapi.editVuln(vuln, **kwargs)
                    else:
                        guiapi.editVulnWeb(vuln, **kwargs)
                    self.setListItems()

    def addValue(self):
        vuln_web_enabled = False
        if self.model_object.class_signature == "Service":
            vuln_web_enabled = True
        dialog = NewVulnDialog(self, callback=self.__addValue, vuln_web_enabled=vuln_web_enabled)
        dialog.exec_loop()
    
    def __addValue(self, *args):
        obj = self.model_object
        if args[0]:
                     
            guiapi.createAndAddVulnWeb(obj, *args[1:])
        else:
            guiapi.createAndAddVuln(obj, *args[1:])
        self.setListItems()

    def removeValue(self):
        for item in self._selected_items: 
            if item.type == "Vuln" or item.type == "VulnWeb":
                vuln = item.getModelObject()
                guiapi.delVuln(vuln.getParent().getID(), vuln.getID())
        self.setListItems()
        self.edition_layout.clear()

    def sizeHint(self):
        return qt.QSize(850, 500)


class CredsDialog(ListableObjecttDialog):
    def __init__(self, parent=None, model_object=None):
        ListableObjecttDialog.__init__(self, parent, "Credentials", model_object, model_object.getCreds(),
                            layout_margin=10, layout_spacing=15, modal=True)

    def setupEditor(self, parent_layout):
        self.edition_layout = CredEditor(self)
        parent_layout.addLayout(self.edition_layout)

    def setListItems(self):
        self.listview.clear()
        self.rootitem = CredRootItem(self.listview, self.title, self.model_object)
        for obj in self.model_object.getCreds():
            self.rootitem.addCred(obj)

    def setEdition(self):
        if self._current_item is not None:
            if self._current_item.type == "Cred":
                self.edition_layout.setCred(self._current_item.getModelObject())
        
    def saveValue(self):
        if self._current_item is not None:
            if self._current_item.type == "Cred":
                cred = self._current_item.getModelObject()
                kwargs = self.edition_layout.getArgs()
                if kwargs["username"] and kwargs["password"]:
                    guiapi.editCred(cred, **kwargs)
                    self.setListItems()

    def addValue(self):
        dialog = NewCredDialog(self, callback=self.__addValue)
        dialog.exec_loop()
    
    def __addValue(self, *args):
        obj = self.rootitem.getModelObject()
        guiapi.createAndAddCred(obj, *args)
        self.setListItems()

    def removeValue(self):
        for item in self._selected_items: 
            if item.type == "Cred":
                cred = item.getModelObject()
                guiapi.delCred(cred.getParent().getID(), cred.getID())
        self.setListItems()
        self.edition_layout.clear()
                    

    def sizeHint(self):
        return qt.QSize(750, 500)


class AboutDialog(BaseDialog):

    def __init__(self, parent):
        BaseDialog.__init__(self, parent, "AboutDialog",
                            layout_margin=15, layout_spacing=10, modal=True)
        self.setCaption( 'About %s' % CONF.getAppname() )

        self.logo = qt.QPixmap( os.path.join(CONF.getImagePath(),"about.png") )
        self.logolabel = qt.QLabel( self )
        self.logolabel.setPixmap( self.logo )
        self.logolabel.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
                                                                           
        self._about_text = u"""%s v%s""" % (CONF.getAppname(),CONF.getVersion())
        self._about_text += "\nInfobyte LLC. All rights reserved"

        self.text = qt.QLabel( self._about_text, self )
        self.text.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )

        self.layout.addWidget( self.logolabel )
        self.layout.addWidget( self.text )
        self.setupButtons({"ok" : None})


                                                                                
class RepositoryConfigDialog(BaseDialog):

    def __init__(self, parent, url="http://example:5984", replication = False, replics = "", callback=None):
        BaseDialog.__init__(self, parent, "RepositoryConfig",
                            layout_margin=25, layout_spacing=20, modal=True)

        self._callback = callback
        
        self.setCaption("Repository Configuration")

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(10)
        self._repourl_label = qt.QLabel("CouchDB (http://127.0.0.1:5984)", hbox1)
        self._repourl_edit = qt.QLineEdit(hbox1)
        if url: self._repourl_edit.setText(url)
        self.layout.addWidget(hbox1)

        hbox2 = qt.QHBox(self)
        hbox2.setSpacing(5)
        self._replicate_label = qt.QLabel("Replication enabled", hbox2)
        self._replicate_edit = qt.QCheckBox(hbox2)
        self._replicate_edit.setChecked(replication)
                                                               
        self.layout.addWidget(hbox2)

        hbox3 = qt.QHBox(self)
        hbox3.setSpacing(10)
        self._replics_label = qt.QLabel("Replics", hbox3)
        self.__replics_edit = qt.QLineEdit(hbox3)
        if replics: self.__replics_edit.setText(replics)
        self.layout.addWidget(hbox3)

        self.__repourl_txt = self._repourl_edit.text()
        self.__is_replicated_bool = self._replicate_edit.isChecked()
        self.__replics_list_txt = self.__replics_edit.text()


        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })

    def getData(self):
        self.__repourl_txt = self._repourl_edit.text()
        self.__is_replicated_bool = self._replicate_edit.isChecked()
        self.__replics_list_txt = self.__replics_edit.text()
        return (self.__repourl_txt.latin1(), 
            self.__is_replicated_bool,
            self.__replics_list_txt.latin1())

    def ok_pressed(self):
        if self._callback is not None:
            self._callback(*self.getData())
        self.accept()

                                                                                

class ExceptionDialog(BaseDialog):

    def __init__(self, parent, text="", callback=None, excection_objects=None):
        BaseDialog.__init__(self, parent, "ExceptionDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
        self._callback = callback
        self._excection_objects = excection_objects
        self.setCaption('Error')

        label1 = qt.QLabel("An unhandled error ocurred...", self )
        label1.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.layout.addWidget(label1)

        exception_textedit = qt.QTextEdit(self)
        exception_textedit.setTextFormat(qt.Qt.LogText)
        exception_textedit.append(text)
        self.layout.addWidget(exception_textedit)

        label2 = qt.QLabel("""Do you want to collect information and send it to Faraday developers?\n\
If you press Cancel the application will just continue.""", self )
        label2.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.layout.addWidget(label2)

        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })
    def ok_pressed(self):
        if self._callback is not None:
            self._callback(*self._excection_objects)
        self.accept()

    def sizeHint(self):
        return qt.QSize(680, 300)
                                                                                

class SimpleDialog(BaseDialog):

    def __init__(self, parent, text="", type="Information"):
        BaseDialog.__init__(self, parent, "SimpleDialog",
                            layout_margin=10, layout_spacing=10, modal=True)
        self.setCaption(type)

                                                   
        self.text = qt.QLabel(self)
        self.text.setTextFormat(qt.Qt.RichText)
        self.text.setText(text.replace("\n", "<br>"))                          
        self.text.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.layout.addWidget( self.text )
        self.setupButtons({"ok" : None})


class ExitDialog(BaseDialog):
    def __init__(self, parent, callback=None,title="Exit", msg="Are you sure?"):
        BaseDialog.__init__(self, parent, "ExitDialog",
                            layout_margin=20, layout_spacing=15, modal=True)
        self.setCaption(title)
                                        
        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        self._message_label = qt.QLabel(msg, hbox1)
        self._message_label.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.layout.addWidget(hbox1)
        self.setupButtons({ "ok" : callback,
                            "cancel" : None
                          })

    def sizeHint(self):
        return qt.QSize(50, 50)

                                                                                

class MessageDialog(BaseDialog):
    def __init__(self, parent, callback=None , title="Are you sure?", msg="Are you sure?", item=None):
        BaseDialog.__init__(self, parent, "ExitDialog",
                            layout_margin=20, layout_spacing=15, modal=True)
        self.setCaption(title)
                                        
        self._callback = callback
        self._item=item
        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        self._message_label = qt.QLabel(msg, hbox1)
        self._message_label.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.layout.addWidget(hbox1)
        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })
    def ok_pressed(self):
        if self._callback is not None:
            self._callback(self._item)
        self.accept()    

    def sizeHint(self):
        return qt.QSize(50, 50)

                                                                                

class VulnDialog(BaseDialog):

    def __init__(self, parent, name="",description="", ref="", callback=None, item=None):
        BaseDialog.__init__(self, parent, "VulnDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
                                                                                     
        self._item = item
        self._callback = callback
        self.setCaption("New vulnerability" if name is "" else "Vuln %s" % item.name)

                      

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        name_label = qt.QLabel("Name", hbox1)
        self._name_edit = qt.QLineEdit(hbox1)
        if name: self._name_edit.setText(name)
        self.layout.addWidget(hbox1)
        
        hbox2 = qt.QHBox(self)
        hbox2.setSpacing(5)
        ref_label = qt.QLabel("Ref", hbox2)
        self._ref_edit = qt.QLineEdit(hbox2)
        if ref: self._ref_edit.setText(ref)
        self.layout.addWidget(hbox2)

        vbox6 = qt.QVBox(self)
        vbox6.setSpacing(5)
        description_label = qt.QLabel("Description:", vbox6 )
                                                                                  
        self._description_edit = qt.QTextEdit(vbox6)
        self._description_edit.setTextFormat(qt.Qt.PlainText)
        if description: self._description_edit.append(description)
        self.layout.addWidget(vbox6)

        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })
    def ok_pressed(self):
        if self._callback is not None:
            if self._name_edit.text() != "":
                self._callback("%s" % self._name_edit.text(),"%s" % self._description_edit.text(),
                "%s" % self._ref_edit.text(),self._item)
                self.accept()
            else:
                dialog = SimpleDialog(self, "Please select a name")
                dialog.exec_loop()

    def sizeHint(self):
        return qt.QSize(600, 400)


class CategoryDialog(BaseDialog):

    def __init__(self, parent, name="", callback=None, item=None):
        BaseDialog.__init__(self, parent, "CategoryDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
                                                                                           
        self._item = item
        self._callback = callback
        self.setCaption("New category" if name is "" else "Category in %s" % item.name)

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        name_label = qt.QLabel("Name", hbox1)
        self._name_edit = qt.QLineEdit(hbox1)
        if name: self._name_edit.setText(name)
        self.layout.addWidget(hbox1)

        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })

    def ok_pressed(self):
        if self._callback is not None:
            if self._name_edit.text() != "":
                self._callback("%s" % self._name_edit.text(), self._item)
                self.accept()
            else:
                dialog = SimpleDialog(self, "Please select a name")
                dialog.exec_loop() 

    def sizeHint(self):
        return qt.QSize(600, 400)

                                                                                

class NoteDialog(BaseDialog):

    def __init__(self, parent, name="", text="", callback=None, item=None):
        BaseDialog.__init__(self, parent, "NoteDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
                                                                                  
        self._item = item
        self._callback = callback
        self.setCaption("New note" if name is "" else "Note %d" % item.id)

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        name_label = qt.QLabel("Name", hbox1)
        self._name_edit = qt.QLineEdit(hbox1)
        if name: self._name_edit.setText(name)
        self.layout.addWidget(hbox1)

        vbox2 = qt.QVBox(self)
        vbox2.setSpacing(3)
        content_label = qt.QLabel("Note content:", vbox2 )
                                                                              
        self._textedit = qt.QTextEdit(vbox2)
        self._textedit.setTextFormat(qt.Qt.PlainText)
        if text: self._textedit.append(text)
        self.layout.addWidget(vbox2)

        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })
    def ok_pressed(self):
        if self._callback is not None:        
            if self._name_edit.text() != "":
                if self._item is not None:
                    self._callback(self._name_edit.text(), self._textedit.text(),self._item)
                else:
                    self._callback(self._name_edit.text(), self._textedit.text())
                self.accept()
            else:
                dialog = SimpleDialog(self, "Please select a name")
                dialog.exec_loop()   

    def sizeHint(self):
        return qt.QSize(600, 400)

                                                                                

            
class NotificationWidget(qt.QLabel):
    def __init__(self, parent, text=""):
        qt.QLabel.__init__(self, parent, "notification")
        pal = qt.QPalette()
        color = qt.QColor(232, 226, 179, qt.QColor.Rgb)
        pal.setColor(qt.QColorGroup.Background, color)
        self.setTextFormat(qt.Qt.RichText)
        self.setText(text.replace("\n", "<br>"))                          
        self.setFrameStyle(qt.QFrame.PopupPanel | qt.QFrame.Plain)
        self.setAlignment( qt.Qt.AlignHCenter | qt.Qt.AlignVCenter )
        self.setPalette(pal)
        
        _w,_h=self._getsize(text)
        self.resize(qt.QSize(_w,_h))
                                                                                          
        self._updatePos(parent)
        
    def _getsize(self, text):
        _tlist=text.split("\n")
        _width=0
        _w=10
        for i in _tlist:
            _size=len(i)
            if _size > _width:
                _width = _size
                if _size > 80 and len(i.split(" ")) <=2:
                    _w=12   
                                                                               
    
        return _width*_w,(28*len(text.split("\n")))
    

    def _updatePos(self, parent):
        pos = qt.QPoint()
        pos.setX(parent.width() - self.width() - 5)
        pos.setY(parent.height() - self.height() - 20)
        self.move(pos)

    def closeNotification(self):
        self.hide()
        parent = self.parent()
        parent.removeChild(self)
        self.destroy()

                                                                                

class WorkspacePropertiesDialog(BaseDialog):

    def __init__(self, parent, text="", callback=None, workspace=None):
        BaseDialog.__init__(self, parent, "WorkspacePropertiesDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
        self._callback = callback
        self.setCaption('Workspace Properties')
                                                                          

        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        self._name_label = qt.QLabel("Name", hbox1)
        self._name_edit = qt.QLineEdit(hbox1)
        self.layout.addWidget(hbox1)

        hbox2 = qt.QHBox(self)
        self._sdate_edit = qt.QDateEdit(hbox2, "start_date")
        self.layout.addWidget(hbox2)

        hbox3 = qt.QHBox(self)
        self._fdate_edit = qt.QDateEdit(hbox3, "ftart_date")
        self.layout.addWidget(hbox3)

        hbox4 = qt.QHBox(self)
        self._shared_checkbox = qt.QCheckBox("Shared", hbox4, "shared")
        self.layout.addWidget(hbox4)

        hbox5 = qt.QHBox(self)
        hbox5.setSpacing(10)
        self._desc_label = qt.QLabel("Description", hbox5)
        self._desc_edit = qt.QTextEdit(hbox5)
        self.layout.addWidget(hbox5)



        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
        })

    def ok_pressed(self):
                                                                                 
                                                        
        if self._callback is not None:
            name = self._name_edit.text()
            description = self._desc_edit.text()
            sdate = self._sdate_edit.date.toString()
            fdate = self._fdate_edit.date.toString()
            shared = self._shared_checkbox.checked
            self._callback()
        self.accept()

    def sizeHint(self):
        return qt.QSize(600, 400)

                                                                                
                                                                         
                                                       
class WorkspaceCreationDialog(BaseDialog):

    def __init__(self, parent, text="", callback=None, workspace=None, workspace_manager=None):
        BaseDialog.__init__(self, parent, "WorkspaceCreationDialog",
                            layout_margin=10, layout_spacing=15, modal=True)
        self._callback = callback
        self.setCaption('New Workspace')
        self._main_window = parent
        
        hbox1 = qt.QHBox(self)
        hbox1.setSpacing(5)
        self._name_label = qt.QLabel("Name", hbox1)
        self._name_edit = qt.QLineEdit(hbox1)
        self.layout.addWidget(hbox1)

        hbox2 = qt.QHBox(self)
        hbox2.setSpacing(10)
        self._desc_label = qt.QLabel("Description", hbox2)
        self._desc_edit = qt.QTextEdit(hbox2)
        self.layout.addWidget(hbox2)

        hbox3 = qt.QHBox(self)
        hbox3.setSpacing(10)
        self._type_label = qt.QLabel("Type", hbox3)
        self._type_combobox = qt.QComboBox(hbox3)
        self._type_combobox.setEditable(False)
        for w in workspace_manager.getAvailableWorkspaceTypes():
            self._type_combobox.insertItem(w)
        self.layout.addWidget(hbox3)

        if len(workspace_manager.getAvailableWorkspaceTypes()) <= 1:
            parent.showPopup("No Couch Configuration available. Config, more workpsaces flavors")

        self.__name_txt = self._name_edit.text()
        self.__desc_txt = self._desc_edit.text()
        self.__type_txt = str(self._type_combobox.currentText())

        self.setupButtons({ "ok" : self.ok_pressed,
                            "cancel" : None
                          })
    def ok_pressed(self):
        res = re.match(r"^[a-z][a-z0-9\_\$()\+\-\/]*$", str(self._name_edit.text()))
        if res:
            if self._callback is not None:
                self.__name_txt = str(self._name_edit.text())
                self.__desc_txt = str(self._desc_edit.text())
                self.__type_txt = str(self._type_combobox.currentText())
                self._callback(self.__name_txt, self.__desc_txt, self.__type_txt)
            self.accept()
        else:
            self._main_window.showPopup("A workspace must be named with all lowercase letters (a-z), digits (0-9) or any of the _$()+-/ characters. The name has to start with a lowercase letter (a-z)") 

                                                                                

class PluginSettingsDialog(BaseDialog, PluginSettingsUi):
    def __init__(self, parent=None, plugin_manager=None):
        BaseDialog.__init__(self, parent, "")
        PluginSettingsUi.__init__(self, parent)

        self._plugin_manager = plugin_manager
        if plugin_manager is not None:
            self._plugin_settings = plugin_manager.getSettings()
        else:
            self._plugin_settings = {}

        self._set_connections()

        self._items = {}
        self._params = {}

        self.t_parameters.horizontalHeader().setStretchEnabled(True, 0)

        self._selected_plugin = None
        self._load_plugin_list()

    def _set_connections(self):
        self.connect(self.lw_plugins, qt.SIGNAL("selectionChanged(QListViewItem*)"), self._show_plugin )
        self.connect(self.lw_plugins, qt.SIGNAL("clicked(QListViewItem*)"),
                     self._show_plugin)
        self.connect(self.t_parameters, qt.SIGNAL("valueChanged(int, int)"),
                     self._set_parameter)
        self.connect(self.bt_ok, qt.SIGNAL("clicked()"),
                     self._update_settings)

    def _load_plugin_list(self):
        if self._plugin_manager is None:
            return

        for plugin_id, params in self._plugin_settings.iteritems():
            new_item = qt.QListViewItem(self.lw_plugins, "%s" % params["name"])
            self._items[new_item] = plugin_id

    def _set_parameter(self, row, col):
        settings = self._plugin_settings[self._selected_plugin]["settings"]
        parameter = self.t_parameters.verticalHeader().label(row)
        value = self.t_parameters.text(row, col)
        settings[str(parameter).strip()] = str(value).strip()

    def _update_settings(self):
        if self._plugin_manager is not None:
            self._plugin_manager.updateSettings(self._plugin_settings)

    def _show_plugin(self, item):
        if item is None:
            return

        self.t_parameters.removeRows(range(self.t_parameters.numRows()))

        plugin_id = self._items[item]
        self._selected_plugin = plugin_id

        params = self._plugin_settings[plugin_id]

        self.le_name.setText(params["name"])
        self.le_version.setText(params["version"])
        self.le_pversion.setText(params["plugin_version"])

        for setting, value in params["settings"].iteritems():
            index = self.t_parameters.numRows()
            self.t_parameters.insertRows(index)

            self.t_parameters.verticalHeader().setLabel(index, setting)
            self.t_parameters.setText(index, 0, str(value))

                                                                                

class VulnsListDialog(BaseDialog, VulnerabilitiesUi):
    def __init__(self, parent=None,item=None):
        BaseDialog.__init__(self, parent, "")
        VulnerabilitiesUi.__init__(self, parent)
        self._vulns = []
        self._setup_signals()
        self._item=item

        self.t_vulns.setColumnReadOnly(0, True)
        self.t_vulns.setColumnReadOnly(1, True)
        self.t_vulns.setColumnReadOnly(2, True)

        self.t_vulns.horizontalHeader().setStretchEnabled(True, 3)

    def add_vuln(self, vuln):
        index = self.t_vulns.numRows()
        self._vulns.append(vuln)
        self.t_vulns.insertRows(index)

        self.t_vulns.setText(index, 0, str(vuln.name))
        self.t_vulns.setText(index, 1, str(vuln.refs))
        self.t_vulns.setText(index, 2, str(vuln.desc))

        self.t_vulns.adjustColumn(0)
        self.t_vulns.adjustColumn(1)
        self.t_vulns.adjustColumn(2)


    def del_vuln(self, vuln):
        
        index = self.t_vulns.currentRow()
        self._vulns.remove(vuln)
        self.t_vulns.removeRows([index])



    def _setup_signals(self):
                                                          
        self.connect(self.t_vulns, SIGNAL("doubleClicked(int,int,int,QPoint)"),self._edit)

        self.connect(self.add_button, SIGNAL("clicked()"), self._add)
        self.connect(self.edit_button, SIGNAL("clicked()"), self._edit)
        self.connect(self.delete_button, SIGNAL("clicked()"), self._delete)
        self.connect(self.list_note_button, SIGNAL("clicked()"), self._list_note)
        self.connect(self.manage_evidence_button, SIGNAL("clicked()"), self._evidence)
        
    
    def _edit(self):
                                       
        if self.t_vulns.currentSelection() != -1:
            _object=self._vulns[self.t_vulns.currentRow()]
            dialog = VulnDialog(self,str(_object.name),str(_object.desc),str(_object.refs),self._editcallback,_object)
            res = dialog.exec_loop()
            
    def _evidence(self):
                                       
        if self.t_vulns.currentSelection() != -1:
            _object=self._vulns[self.t_vulns.currentRow()]
            _object.object = _object
            dialog = EvidencesListDialog(self, _object)
                                             
                                            
            dialog.exec_loop()
            
    def _list_note(self):
                                       
        if self.t_vulns.currentSelection() != -1:
            _object=self._vulns[self.t_vulns.currentRow()]
            _object.object = _object
            dialog = NotesListDialog(self, _object)
                                             
                                            
            dialog.exec_loop()
            
    def _editcallback(self,name,desc,ref,item):

        item.name=name
        item.desc=desc
        item.ref=ref
        
        self.t_vulns.setText(self.t_vulns.currentRow(), 0, name)
        self.t_vulns.setText(self.t_vulns.currentRow(), 1, ref)
        self.t_vulns.setText(self.t_vulns.currentRow(), 2, desc)

    def _newcallback(self, name, desc, ref, item):
        _parent=self._item.object.getParent()
        
        api.devlog("newVuln (%s) (%s) (%s) (%s) " % (name, desc, ref, item.object.getName(),))
        
        _newvuln=api.newVuln(name,desc,ref)

        if item.type == "Application":
            api.addVulnToApplication(_newvuln,_parent.name,item.object.getName())
        elif item.type == "Interface":
            api.addVulnToInterface(_newvuln,_parent.name,item.object.getName())
        elif item.type == "Host":
            api.addVulnToHost(_newvuln,item.object.getName())
        elif item.type == "Service":
            api.addVulnToService(_newvuln,_parent.name,item.object.getName())
        
                                                          
        self.add_vuln(_newvuln)   
        
    def _add(self):
        if self._item is not None and self._item.object is not None:
            dialog = VulnDialog(self,callback=self._newcallback,item=self._item)
            res = dialog.exec_loop()
            
    
    def _delete(self):
        if self.t_vulns.currentSelection() != -1:
            _vuln=self._vulns[self.t_vulns.currentRow()]
            _parent=_vuln._parent
                                                                                                  
            
            if isinstance(_parent,hosts.HostApplication):
                api.delVulnFromApplication(_vuln.getID(),_parent.getParent().name,_parent.name)
            elif isinstance(_parent,hosts.Interface):
                api.delVulnFromInterface(_vuln.getID(),_parent.getParent().name,_parent.name)
            elif isinstance(_parent,hosts.Host):
                api.delVulnFromHost(_vuln.getID(),_parent.name)
            elif isinstance(_parent,hosts.Service):
                api.delVulnFromService(_vuln.getID(),_parent.getParent().name,_parent.name)
        
                                                                 
            self.del_vuln(_vuln)
        

                                                                                

class PreferencesDialog(BaseDialog, PreferencesUi):
    def __init__(self, parent=None):
        BaseDialog.__init__(self, parent, "")
        PreferencesUi.__init__(self, parent)
        self._main_window = parent

        self._fdb = qt.QFontDatabase()
        self._families = self._fdb.families()
        self.cb_font_family.insertStringList(self._families)

        self._styles = None
        self._sizes = None
        
        self._family = None
        self._style = None
        self._size = None


        self._set_connections()
        self._load_styles(0)
        self._load_sizes(0)
        
    def _set_connections(self):
        self.connect(self.cb_font_family, SIGNAL("activated(int)"),
                     self._load_styles)
        self.connect(self.cb_font_style, SIGNAL("activated(int)"),
                     self._load_sizes)
        self.connect(self.cb_font_size, SIGNAL("activated(int)"),
                     self._change_size)
        self.connect(self.bt_ok, SIGNAL("clicked()"),
                     self.accept)
        self.connect(self.bt_cancel, SIGNAL("clicked()"),
                     self.reject)

    def _load_styles(self, index):
        self._family = self._families[index]
        self.cb_font_style.clear()
        self._styles = self._fdb.styles(self._family)
        self.cb_font_style.insertStringList(self._styles)
        self._update_font()

    def _load_sizes(self, index):
        self._style = self._styles[index]
        self.cb_font_size.clear()
        self._sizes = self._fdb.smoothSizes(self._family, self._style)
        string_list = QStringList()
        [string_list.append(str(size)) for size in self._sizes]
        self.cb_font_size.insertStringList(string_list)
        self._update_font()

    def _change_size(self, index):
        self._size = self._sizes[index]
        self._update_font()

    def _update_font(self):
        font = self.le_example.font()
        if self._family is not None:
            font.setFamily(self._family)
        if self._size is not None:
            font.setPointSize(self._size)
        if self._style is not None:
            isItalic = self._fdb.italic(self._family, self._style)
            font.setItalic(isItalic)
            isBold = self._fdb.bold(self._family, self._style)
            font.setBold(isBold)
            weight = self._fdb.weight(self._family, self._style)
            font.setWeight(weight)
        self.le_example.setFont(font)
        self._main_window.shell_font = font

                                                                                

class NotesListDialog(BaseDialog, NotesListUI):

    def __init__(self, parent, item=None):
        BaseDialog.__init__(self, parent, "NotesListDialog", modal=True)
        NotesListUI.__init__(self, parent)
        self.notes_table.setColumnReadOnly(0, True)
        self.notes_table.setColumnReadOnly(1, True)
        self._notes = []
        self._setup_signals()
        self._item = item                                                           
        if item is not None and item.object is not None:
            for n in item.object.getNotes():
                self.add_note_to_table(n)
        
    def add_note_to_table(self, note):
        index = self.notes_table.numRows()
        self._notes.append(note)
        self.notes_table.insertRows(index)
        self.notes_table.setText(index, 0, note.name)
        self.notes_table.setText(index, 1, note.text)
        self.notes_table.adjustColumn(0)
        self.notes_table.adjustColumn(1)
        self.notes_table.adjustRow(index)
    
    def _setup_signals(self):
                                                          
                                                                                    
                              

        self.connect(self.add_button, SIGNAL("clicked()"), self._add_note)
        self.connect(self.edit_button, SIGNAL("clicked()"), self._edit_note)
        self.connect(self.delete_button, SIGNAL("clicked()"), self._delete_note)
        self.connect(self.list_note_button, SIGNAL("clicked()"), self._list_note)
    
    def _edit_note(self):
        if self.notes_table.currentSelection() != -1:
            _object=self._notes[self.notes_table.currentRow()]
            dialog = NoteDialog(self,_object.name,_object.text,self._editcallbackNote,_object)
            res = dialog.exec_loop()

    def _list_note(self):
                                       
        if self.notes_table.currentSelection() != -1:
            _object=self._notes[self.notes_table.currentRow()]
            _object.object = _object
            dialog = NotesListDialog(self, _object)
                                             
                                            
            dialog.exec_loop()

    def _editcallbackNote(self,name,text,item):
        item.name = name
        item.text = text
        self.notes_table.setText(self.notes_table.currentRow(), 0, name)
        self.notes_table.setText(self.notes_table.currentRow(), 1, text)

    def _newcallbackNote(self, name, text, item):
        _parent=self._item.object.getParent()
        
        api.devlog("newNote (%s) (%s) (%s)  " % (name, text, item.object.getName(),))
        
        _newnote=api.newNote(name,text)
        
        if item.object.class_signature == "HostApplication":
            api.addNoteToApplication(_newnote,_parent.name,item.object.getName())
        elif item.object.class_signature == "Interface":
            api.addNoteToInterface(_newnote,_parent.name,item.object.getName())
        elif item.object.class_signature == "Host":
            api.addNoteToHost(_newnote,item.object.getName())
        elif item.object.class_signature == "Service":
            api.addNoteToService(_newnote,_parent.name,item.object.getName())
        else:
                                                                                            
                                                                                    
            item.object.addNote(_newnote)
        
        self.add_note_to_table(_newnote)
        
    def _add_note(self):
        if self._item is not None and self._item.object is not None:
            dialog = NoteDialog(self,callback=self._newcallbackNote,item=self._item)
            res = dialog.exec_loop()
            
    
    def _delete_note(self):
        
        _object=self._notes[self.notes_table.currentRow()]
        if self.notes_table.currentSelection() != -1:
            _note=self._notes[self.notes_table.currentRow()]
            _parent=_note._parent
                
            if _parent.class_signature == "HostApplication":
                api.delNoteFromApplication(_note.getID(),_parent.getParent().name,_parent.name)
            elif _parent.class_signature == "Interface":
                api.delNoteFromInterface(_note.getID(),_parent.getParent().name,_parent.name)
            elif _parent.class_signature == "Host":
                api.delNoteFromHost(_note.getID(),_parent.name)
            elif _parent.class_signature == "Service":
                api.delNoteFromService(_note.getID(),_parent.getParent().name,_parent.name)
            else:
                _parent.delNote(_note.getID())
                
        
                                                                 
            self.del_note(_note)
        

    def del_note(self, note):
        
        index = self.notes_table.currentRow()
        self._notes.remove(note)
        self.notes_table.removeRows([index])

                                                                              

                                                                                

class EvidencesListDialog(BaseDialog, EvidencesListUI):

    def __init__(self, parent, item=None):
        BaseDialog.__init__(self, parent, "EvidencesListDialog", modal=True)
        EvidencesListUI.__init__(self, parent)
        self.evidences_table.setColumnReadOnly(0, True)
        self.evidences_table.setColumnReadOnly(1, True)
        self._setup_signals()
        self._item = item                                                               
        if item is not None and item.object is not None:
            for n in item.object.evidences:
                self.add_evidence_to_table(n)
        
    def add_evidence_to_table(self, evidence):
        index = self.evidences_table.numRows()
        self.evidences_table.insertRows(index)
        self.evidences_table.setText(index, 0, str(index))
        self.evidences_table.setText(index, 1, evidence)
        self.evidences_table.adjustColumn(0)
        self.evidences_table.adjustColumn(1)
        self.evidences_table.adjustRow(index)
    
    def _setup_signals(self):
                                                          
                                                                                        
                                  

        self.connect(self.add_button, SIGNAL("clicked()"), self._add_evidence)
        self.connect(self.delete_button, SIGNAL("clicked()"), self._delete_evidence)

    def _newcallbackEvidence(self, name, item):
        
        d_path = api.addEvidence("%s" % name)
        if d_path is not False:
            self._item.object.evidences.append(d_path)
            self.add_evidence_to_table(d_path)
        
    def _add_evidence(self):
        if self._item is not None and self._item.object is not None:
            filename =  QFileDialog.getOpenFileName(
                        CONF.getDefaultTempPath(),
                        "Images Files  (*.png)",
                        None,
                        "open file dialog",
                        "Choose a file to add in the evidence" );
            
            if (filename):
                self._newcallbackEvidence(filename,self._item)
                for n in self._item.object.evidences:
                    api.devlog("Los items screenshot son:" + n)
            
            
    def _delete_evidence(self):
        
        if self.evidences_table.currentSelection() != -1:

            index = self.evidences_table.currentRow()
            _evidence=self._item.object.evidences[index]
            self._item.object.evidences.remove(_evidence)
            api.delEvidence(_evidence)
            self.evidences_table.removeRows([index])
            self._updateIds()
            for n in self._item.object.evidences:
                api.devlog("Los items screenshot son:" + n)
                
    def _updateIds(self):
        for i in range(0,self.evidences_table.numRows()):
            self.evidences_table.setText(i , 0, str(i))
        


                                                                                     
