'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
# -*- coding: utf-8 -*-

                                                                     
 
                                   
                                                          
 
                                                      


from qt import *


class PreferencesUi(QDialog):
    def __init__(self,parent = None,name = None,modal = 0,fl = 0):
        QDialog.__init__(self,parent,name,modal,fl)

        if not name:
            self.setName("PreferencesUi")


        PreferencesUiLayout = QGridLayout(self,1,1,11,6,"PreferencesUiLayout")

        layout18 = QHBoxLayout(None,0,6,"layout18")

        self.textLabel1 = QLabel(self,"textLabel1")
        layout18.addWidget(self.textLabel1)

        self.cb_font_family = QComboBox(0,self,"cb_font_family")
        self.cb_font_family.setMinimumSize(QSize(300,0))
        layout18.addWidget(self.cb_font_family)

        PreferencesUiLayout.addLayout(layout18,0,0)

        layout19_2 = QHBoxLayout(None,0,6,"layout19_2")

        self.textLabel1_2_2 = QLabel(self,"textLabel1_2_2")
        layout19_2.addWidget(self.textLabel1_2_2)

        self.cb_font_size = QComboBox(0,self,"cb_font_size")
        self.cb_font_size.setMinimumSize(QSize(300,0))
        layout19_2.addWidget(self.cb_font_size)

        PreferencesUiLayout.addLayout(layout19_2,2,0)

        layout19 = QHBoxLayout(None,0,6,"layout19")

        self.textLabel1_2 = QLabel(self,"textLabel1_2")
        layout19.addWidget(self.textLabel1_2)

        self.cb_font_style = QComboBox(0,self,"cb_font_style")
        self.cb_font_style.setMinimumSize(QSize(300,0))
        layout19.addWidget(self.cb_font_style)

        PreferencesUiLayout.addLayout(layout19,1,0)

        layout21 = QHBoxLayout(None,0,6,"layout21")
        spacer6 = QSpacerItem(121,21,QSizePolicy.Expanding,QSizePolicy.Minimum)
        layout21.addItem(spacer6)

        layout20 = QHBoxLayout(None,0,6,"layout20")

        self.bt_ok = QPushButton(self,"bt_ok")
        layout20.addWidget(self.bt_ok)

        self.bt_cancel = QPushButton(self,"bt_cancel")
        layout20.addWidget(self.bt_cancel)
        layout21.addLayout(layout20)

        PreferencesUiLayout.addLayout(layout21,4,0)

        self.le_example = QLineEdit(self,"le_example")
        self.le_example.setFrameShadow(QLineEdit.Sunken)
        self.le_example.setAlignment(QLineEdit.AlignHCenter)
        self.le_example.setReadOnly(1)

        PreferencesUiLayout.addWidget(self.le_example,3,0)

        self.languageChange()

        self.resize(QSize(436,217).expandedTo(self.minimumSizeHint()))
        self.clearWState(Qt.WState_Polished)


    def languageChange(self):
        self.setCaption(self.__tr("Preferences"))
        self.textLabel1.setText(self.__tr("Font:"))
        self.textLabel1_2_2.setText(self.__tr("Size:"))
        self.textLabel1_2.setText(self.__tr("Style:"))
        self.bt_ok.setText(self.__tr("Ok"))
        self.bt_cancel.setText(self.__tr("Cancel"))
        self.le_example.setText(self.__tr("This is an example."))


    def __tr(self,s,c = None):
        return qApp.translate("PreferencesUi",s,c)
