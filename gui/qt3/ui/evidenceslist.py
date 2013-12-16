'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
# -*- coding: utf-8 -*-

                                                                       
 
                                   
                                                          
 
                                                      


from qt import *
from qttable import QTable


class EvidencesListUI(QDialog):
    def __init__(self,parent = None,name = None,modal = 0,fl = 0):
        QDialog.__init__(self,parent,name,modal,fl)

        if not name:
            self.setName("EvidencesListUI")

        self.evidences_table = QTable(self,"evidences_table")
        self.evidences_table.setNumCols(self.evidences_table.numCols() + 1)
        self.evidences_table.horizontalHeader().setLabel(self.evidences_table.numCols() - 1,self.__tr("Id"))
        self.evidences_table.setNumCols(self.evidences_table.numCols() + 1)
        self.evidences_table.horizontalHeader().setLabel(self.evidences_table.numCols() - 1,self.__tr("Path"))
        self.evidences_table.setGeometry(QRect(20,20,510,360))
        self.evidences_table.setMinimumSize(QSize(300,0))
        self.evidences_table.setResizePolicy(QTable.AutoOne)
        self.evidences_table.setVScrollBarMode(QTable.AlwaysOn)
        self.evidences_table.setNumRows(0)
        self.evidences_table.setNumCols(2)

        LayoutWidget = QWidget(self,"layout7")
        LayoutWidget.setGeometry(QRect(90,400,377,29))
        
        layout7 = QHBoxLayout(LayoutWidget,5,5,"layout7")

        self.add_button = QPushButton(LayoutWidget,"add_button")
        layout7.addWidget(self.add_button)
        spacer = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer)

        self.delete_button = QPushButton(LayoutWidget,"delete_button")
        layout7.addWidget(self.delete_button)

        self.languageChange()

        self.resize(QSize(555,447).expandedTo(self.minimumSizeHint()))
        self.clearWState(Qt.WState_Polished)


    def languageChange(self):
        self.setCaption(self.__tr("Evidences"))
        self.evidences_table.horizontalHeader().setLabel(0,self.__tr("Id"))
        self.evidences_table.horizontalHeader().setLabel(1,self.__tr("Path"))
        self.add_button.setText(self.__tr("Add"))
        self.delete_button.setText(self.__tr("Delete"))


    def __tr(self,s,c = None):
        return qApp.translate("EvidencesListUI",s,c)
