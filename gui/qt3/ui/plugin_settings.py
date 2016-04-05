'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
# -*- coding: utf-8 -*-

from qt import *
from qttable import QTable
from model.api import devlog


class PluginSettingsUi(QDialog):
    def __init__(self,parent = None,name = None,modal = 0,fl = 0):
        QDialog.__init__(self,parent,name,modal,fl)

        if not name:
            self.setName("PluginSettingsUi")

        self.setSizeGripEnabled(1)

        PluginSettingsUiLayout = QGridLayout(self,1,1,11,6,"PluginSettingsUiLayout")

        Layout1 = QHBoxLayout(None,0,6,"Layout1")
        Horizontal_Spacing2 = QSpacerItem(20,20,QSizePolicy.Expanding,QSizePolicy.Minimum)
        Layout1.addItem(Horizontal_Spacing2)

        self.bt_ok = QPushButton(self,"bt_ok")
        self.bt_ok.setAutoDefault(1)
        self.bt_ok.setDefault(1)
        Layout1.addWidget(self.bt_ok)

        self.bt_cancel = QPushButton(self,"bt_cancel")
        self.bt_cancel.setAutoDefault(1)
        Layout1.addWidget(self.bt_cancel)

        PluginSettingsUiLayout.addMultiCellLayout(Layout1,1,1,0,1)

        self.lw_plugins = QListView(self,"lw_plugins")
        self.lw_plugins.addColumn(self.__tr("Plugin"))
        self.lw_plugins.header().setClickEnabled(0,self.lw_plugins.header().count() - 1)
        self.lw_plugins.setMinimumSize(QSize(300,0))
        self.lw_plugins.setMaximumSize(QSize(300,32767))
        self.lw_plugins.setResizePolicy(QListView.AutoOneFit)
        self.lw_plugins.setResizeMode(QListView.LastColumn)

        PluginSettingsUiLayout.addWidget(self.lw_plugins,0,0)

        self.frame3 = QFrame(self,"frame3")
        self.frame3.setMinimumSize(QSize(330,0))
        self.frame3.setFrameShape(QFrame.StyledPanel)
        self.frame3.setFrameShadow(QFrame.Raised)
        frame3Layout = QGridLayout(self.frame3,1,1,11,6,"frame3Layout")

        self.line1 = QFrame(self.frame3,"line1")
        self.line1.setFrameShape(QFrame.HLine)
        self.line1.setFrameShadow(QFrame.Sunken)
        self.line1.setFrameShape(QFrame.HLine)

        frame3Layout.addWidget(self.line1,3,0)

        self.t_parameters = QTable(self.frame3,"t_parameters")
        self.t_parameters.setSelectionMode(QTable.NoSelection)
        self.t_parameters.setNumCols(self.t_parameters.numCols() + 1)
        self.t_parameters.horizontalHeader().setLabel(self.t_parameters.numCols() - 1,self.__tr("Value"))
        self.t_parameters.horizontalHeader().setClickEnabled(False)
        self.t_parameters.setNumRows(self.t_parameters.numRows() + 1)
        self.t_parameters.verticalHeader().setLabel(self.t_parameters.numRows() - 1,self.__tr("Default                "))
        self.t_parameters.setMinimumSize(QSize(300,0))
        self.t_parameters.setResizePolicy(QTable.Default)
        self.t_parameters.setVScrollBarMode(QTable.AlwaysOn)
        self.t_parameters.setNumRows(1)
        self.t_parameters.setNumCols(1)
        self.t_parameters.setSorting(1)

        frame3Layout.addWidget(self.t_parameters,3,0)

        layout5 = QHBoxLayout(None,0,6,"layout5")

        self.label_name = QLabel(self.frame3,"label_name")
        self.label_name.setMinimumSize(QSize(67,0))
        self.label_name.setMaximumSize(QSize(67,32767))
        label_name_font = QFont(self.label_name.font())
        label_name_font.setBold(1)
        self.label_name.setFont(label_name_font)
        layout5.addWidget(self.label_name)

        self.le_name = QLineEdit(self.frame3,"le_name")
        self.le_name.setMinimumSize(QSize(250,0))
        self.le_name.setReadOnly(1)
        layout5.addWidget(self.le_name)

        frame3Layout.addLayout(layout5,0,0)

        layout6 = QHBoxLayout(None,0,6,"layout6")

        self.label_version = QLabel(self.frame3,"label_version")
        self.label_version.setMinimumSize(QSize(67,0))
        self.label_version.setMaximumSize(QSize(67,32767))
        label_version_font = QFont(self.label_version.font())
        label_version_font.setBold(1)
        self.label_version.setFont(label_version_font)
        layout6.addWidget(self.label_version)

        self.le_version = QLineEdit(self.frame3,"le_version")
        self.le_version.setMinimumSize(QSize(250,0))
        self.le_version.setReadOnly(1)
        layout6.addWidget(self.le_version)

        frame3Layout.addLayout(layout6,1,0)

        layout7 = QHBoxLayout(None,0,6,"layout7")

        self.label_pversion = QLabel(self.frame3,"label_pversion")
        self.label_pversion.setMinimumSize(QSize(67,0))
        self.label_pversion.setMaximumSize(QSize(67,32767))
        label_pversion_font = QFont(self.label_pversion.font())
        label_pversion_font.setBold(1)
        self.label_pversion.setFont(label_pversion_font)
        layout7.addWidget(self.label_pversion)

        self.le_pversion = QLineEdit(self.frame3,"le_pversion")
        self.le_pversion.setMinimumSize(QSize(250,0))
        self.le_pversion.setReadOnly(1)
        layout7.addWidget(self.le_pversion)

        frame3Layout.addLayout(layout7,2,0)

        PluginSettingsUiLayout.addWidget(self.frame3,0,1)

        self.languageChange()

        self.resize(QSize(782,593).expandedTo(self.minimumSizeHint()))
        self.clearWState(Qt.WState_Polished)

        self.connect(self.bt_ok,SIGNAL("clicked()"),self.accept)
        self.connect(self.bt_cancel,SIGNAL("clicked()"),self.reject)


    def languageChange(self):
        self.setCaption(self.__tr("Plugin Settings"))
        self.bt_ok.setText(self.__tr("&OK"))
        self.bt_ok.setAccel(QKeySequence(QString.null))
        self.bt_cancel.setText(self.__tr("&Cancel"))
        self.bt_cancel.setAccel(QKeySequence(QString.null))
        self.lw_plugins.header().setLabel(0,self.__tr("Plugin"))
        self.t_parameters.horizontalHeader().setLabel(0,self.__tr("Value"))
        self.t_parameters.verticalHeader().setLabel(0,self.__tr("Default                "))
        self.label_name.setText(self.__tr("Name:"))
        self.label_version.setText(self.__tr("Tool:"))
        self.label_pversion.setText(self.__tr("Plugin:"))

    def lv_parameters_currentChanged(self,a0):
        devlog("PluginSettingsUi.lv_parameters_currentChanged(QListViewItem*): Not implemented yet")

    def __tr(self,s,c = None):
        return qApp.translate("PluginSettingsUi",s,c)
