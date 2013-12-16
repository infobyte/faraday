# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

                                                                         
 
                                   
                                                          
 
                                                      


from qt import *
from qttable import QTable


class VulnerabilitiesUi(QDialog):
    def __init__(self,parent = None,name = None,modal = 0,fl = 0):
        QDialog.__init__(self,parent,name,modal,fl)

        if not name:
            self.setName("VulnerabilitiesUi")

                                        

                                                                                       

        self.t_vulns = QTable(self,"t_vulns")
        self.t_vulns.setNumCols(self.t_vulns.numCols() + 1)
        self.t_vulns.horizontalHeader().setLabel(self.t_vulns.numCols() - 1,self.__tr("Name"))
        self.t_vulns.setNumCols(self.t_vulns.numCols() + 1)
        self.t_vulns.horizontalHeader().setLabel(self.t_vulns.numCols() - 1,self.__tr("Refs"))
        self.t_vulns.setNumCols(self.t_vulns.numCols() + 1)
        self.t_vulns.horizontalHeader().setLabel(self.t_vulns.numCols() - 1,self.__tr("Description"))
        self.t_vulns.setMinimumSize(QSize(700,0))
        self.t_vulns.setResizePolicy(QTable.AutoOne)
        self.t_vulns.setVScrollBarMode(QTable.AlwaysOn)
        self.t_vulns.setNumRows(0)
        self.t_vulns.setNumCols(3)

                                                            
        LayoutWidget = QWidget(self,"layout7")
        LayoutWidget.setGeometry(QRect(90,500,450,29))
        
                                                                                                                 
        layout7 = QHBoxLayout(LayoutWidget,5,5,"layout7")

        self.add_button = QPushButton(LayoutWidget,"add_button")
        layout7.addWidget(self.add_button)
        spacer6_2 = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer6_2)

        self.edit_button = QPushButton(LayoutWidget,"edit_button")
        layout7.addWidget(self.edit_button)
        spacer6 = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer6)

        self.delete_button = QPushButton(LayoutWidget,"delete_button")
        layout7.addWidget(self.delete_button)
        
        spacer6_3 = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer6_3)

        self.list_note_button = QPushButton(LayoutWidget,"list_note_button")
        layout7.addWidget(self.list_note_button)

        spacer7_3 = QSpacerItem(21,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout7.addItem(spacer7_3)

        self.manage_evidence_button = QPushButton(LayoutWidget,"manage_evidence_button")
        layout7.addWidget(self.manage_evidence_button)

        self.languageChange()
        
        
        self.resize(QSize(733,550).expandedTo(self.minimumSizeHint()))
        self.clearWState(Qt.WState_Polished)


    def languageChange(self):
        self.setCaption(self.__tr("Vulnerability List"))
        self.t_vulns.horizontalHeader().setLabel(0,self.__tr("Name"))
        self.t_vulns.horizontalHeader().setLabel(1,self.__tr("Refs"))
        self.t_vulns.horizontalHeader().setLabel(2,self.__tr("Description"))
        self.add_button.setText(self.__tr("New"))
        self.edit_button.setText(self.__tr("Edit"))
        self.delete_button.setText(self.__tr("Delete"))
        self.list_note_button.setText(self.__tr("List Notes"))
        self.manage_evidence_button.setText(self.__tr("Evidence"))


    def __tr(self,s,c = None):
        return qApp.translate("VulnerabilitiesUi",s,c)
