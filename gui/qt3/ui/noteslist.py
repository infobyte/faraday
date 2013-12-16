'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
# -*- coding: utf-8 -*-

                                                                   
 
                                   
                                                          
 
                                                      


from qt import *
from qttable import QTable


class NotesListUI(QDialog):
    def __init__(self,parent = None,name = None,modal = 0,fl = 0):
        QDialog.__init__(self,parent,name,modal,fl)

        if not name:
            self.setName("NotesListUI")

        self.notes_table = QTable(self,"notes_table")
        self.notes_table.setNumCols(self.notes_table.numCols() + 1)
        self.notes_table.horizontalHeader().setLabel(self.notes_table.numCols() - 1,self.__tr("Name"))
        self.notes_table.setNumCols(self.notes_table.numCols() + 1)
        self.notes_table.horizontalHeader().setLabel(self.notes_table.numCols() - 1,self.__tr("Content"))
        self.notes_table.setGeometry(QRect(20,20,510,360))
        self.notes_table.setMinimumSize(QSize(300,0))
        self.notes_table.setResizePolicy(QTable.AutoOne)
        self.notes_table.setVScrollBarMode(QTable.AlwaysOn)
        self.notes_table.setNumRows(0)
        self.notes_table.setNumCols(2)

        LayoutWidget = QWidget(self,"layout7")
        LayoutWidget.setGeometry(QRect(90,400,377,29))
        
                                                                                                                 
        layout7 = QHBoxLayout(LayoutWidget,5,5,"layout7")

        self.add_button = QPushButton(LayoutWidget,"add_button")
        layout7.addWidget(self.add_button)
        spacer = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer)

        self.edit_button = QPushButton(LayoutWidget,"edit_button")
        layout7.addWidget(self.edit_button)
        layout7.addItem(spacer)

        self.delete_button = QPushButton(LayoutWidget,"delete_button")
        layout7.addWidget(self.delete_button)
        layout7.addItem(spacer)
        
        self.list_note_button = QPushButton(LayoutWidget,"list_note_button")
        layout7.addWidget(self.list_note_button)

        self.languageChange()

        self.resize(QSize(555,447).expandedTo(self.minimumSizeHint()))
        self.clearWState(Qt.WState_Polished)


    def languageChange(self):
        self.setCaption(self.__tr("Notes"))
        self.notes_table.horizontalHeader().setLabel(0,self.__tr("Name"))
        self.notes_table.horizontalHeader().setLabel(1,self.__tr("Content"))
        self.add_button.setText(self.__tr("New"))
        self.edit_button.setText(self.__tr("Edit"))
        self.delete_button.setText(self.__tr("Delete"))
        self.list_note_button.setText(self.__tr("List Notes"))


    def __tr(self,s,c = None):
        return qApp.translate("NotesListUI",s,c)
