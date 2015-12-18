'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import qt
import os
from gui.qt3.dialogs import BaseDialog

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()


class ConfigurationPage(qt.QVBox):
    def __init__(self, parent=None):
        super(ConfigurationPage, self).__init__(parent)
        configGroup = qt.QHGroupBox("Server configuration", self)
        serverLabel = qt.QLabel("Server:", configGroup)
        serverCombo = qt.QComboBox(configGroup)
        serverCombo.insertItem("Trolltech (Australia)")
        serverCombo.insertItem("Trolltech (Germany)")
        serverCombo.insertItem("Trolltech (Norway)")
        serverCombo.insertItem("Trolltech (People's Republic of China)")
        serverCombo.insertItem("Trolltech (USA)")
                           

class UpdatePage(qt.QVBox):
    def __init__(self, parent=None):
        super(UpdatePage, self).__init__(parent)

        updateGroup = qt.QVGroupBox("Package selection", self)
        systemCheckBox = qt.QCheckBox("Update system", updateGroup)
        appsCheckBox = qt.QCheckBox("Update applications", updateGroup)
        docsCheckBox = qt.QCheckBox("Update documentation", updateGroup)

        packageGroup = qt.QHGroupBox("Existing packages", self)
        packageList = qt.QListView(packageGroup)               
        packageList.addColumn("")
        packageList.setColumnWidthMode(0, qt.QListView.Maximum)
        packageList.setColumnWidth(0, packageList.width())

        qtItem = qt.QListViewItem(packageList)                              
        qtItem.setText(0, "Qt")
        qsaItem = qt.QListViewItem(packageList)
        qsaItem.setText(0, "QSA")
        teamBuilderItem = qt.QListViewItem(packageList)
        teamBuilderItem.setText(0, "Teambuilder")
        self.setSpacing(12)
        startUpdateButton = qt.QPushButton("Start update", self)
                                 


class ConfigDialog(BaseDialog):
    def __init__(self, parent=None, configuration=None):
        BaseDialog.__init__(self, parent, "Config Dialog",
                            layout_margin=10, layout_spacing=15, modal=True)

        self.configuration = configuration

        hbox = qt.QHBox(self)

        self.contentsWidget = qt.QIconView(hbox)               

                                                               
                                                          
                                                             
        self.contentsWidget.setMaximumWidth(128)
                                           

        self.pagesWidget = qt.QWidgetStack(hbox)                         
        self.pagesWidget.addWidget(ConfigurationPage(), 0)
        self.pagesWidget.addWidget(UpdatePage(), 1)
        self.pagesWidget.setSizePolicy(qt.QSizePolicy(qt.QSizePolicy.Expanding, qt.QSizePolicy.Expanding))
                                                

        self.createIcons()
        hbox.setStretchFactor(self.contentsWidget, 0)
        hbox.setStretchFactor(self.pagesWidget, 10)
        self.layout.addWidget(hbox)

                                                                           
        self.setupButtons({
            "ok": None,
            "cancel" : self.close,
            })


    def changePage(self, item):
        if item:
            current = self.contentsWidget.currentItem()
            self.pagesWidget.raiseWidget(self.contentsWidget.index(current))

    def createIcons(self):
        configButton = qt.QIconViewItem(self.contentsWidget)
        configButton.setPixmap(qt.QPixmap(os.path.join(CONF.getIconsPath(), 'config.png')))
        configButton.setText("Configuration")
                                                                             

                                                                                    

        updateButton = qt.QIconViewItem(self.contentsWidget)
        updateButton.setPixmap(qt.QPixmap(os.path.join(CONF.getIconsPath(), 'update.png')))
        updateButton.setText("Update")
                                                                             
                                                                                    

        self.connect(self.contentsWidget, qt.SIGNAL('clicked(QIconViewItem*)'), self.changePage)

    def sizeHint(self):
        return qt.QSize(600, 350)
