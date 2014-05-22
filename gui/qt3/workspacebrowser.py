#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import sys
import os
import qt
import qttable
from model.controller import modelactions
import model.api as api
from gui.qt3.dialogs import WorkspacePropertiesDialog
from gui.qt3.dialogs import WorkspaceCreationDialog

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class WorkspaceListViewItem(qt.QListViewItem):
    """Item for displaying in the WorkspaceTreeWindow."""

    def __init__(self, qtparent,  name, is_active, workspace_type):
        qt.QListViewItem.__init__(self, qtparent)
                                   
        self.setRenameEnabled(0, False)
        self.index = 0
        self.is_active = is_active
        self.workspace_type = workspace_type
        self.objname = name
        self.name = "%s (%s)" % (self.objname , self.workspace_type.replace("WorkspaceOn",""))
        self.setDragEnabled(False)
        self.setDropEnabled(False)
        self._setIcon() 
        
    
    def _setIcon(self):
        active = self.is_active
        icon_name = "FolderBlue-20.png" if active else "FolderSteel-20.png"
        icon_path = os.path.join(CONF.getIconsPath(), icon_name)
        pm = qt.QPixmap(icon_path)
        self.setPixmap(0, pm)


    def setText(self, col, text):
        """Update name of widget if rename is called.""" 
        if col == 0:
            try:
                self.widget.rename( unicode(text) )
            except ValueError:
                                      
                text = self.widget.name

        qt.QListViewItem.setText(self, col, text)

    def rename(self):
        """Rename the listviewitem."""
        self.startRename(0)

                                                            
               
    def compare(self, i, col, ascending):
        """
        #Always sort according to the index value.
        """
        a = [-1, 1][ascending]
                            
        if self.name < i.name:
            return -1*a
        elif self.name > i.name:
            return 1*a
        else:
            return 0

    def text(self, column):
        """Get the text in a particular column."""
        if column == 0:
            return self.name
        return ''


                                                                                

class WorkspaceListView(qt.QListView):

    def __init__(self, parent):
        qt.QListView.__init__(self, parent)
        self.setSelectionMode(qt.QListView.Extended)
    
                                       
                                                               
                                                                 
                                                                                                                

    def dragObject(self):
                                                                   
                                                                          
                                               
        return False

    def selectWidget(self, widget):
        """Find the widget in the list and select it."""

                                                                   
                       
        iter = qt.QListViewItemIterator(self)

        found = None
        while True:
            item = iter.current()
            if item == None:
                break
            if item.widget == widget:
                found = item
                break
            iter += 1

        if found:
            self.ensureItemVisible(found)
            self.setSelected(found, True)

                                                                                
class WorkspaceTreeWindow(qt.QVBox):

    def __init__(self, parent, caption="", manager=None):
        qt.QVBox.__init__(self, parent)
        self.setName(caption)
        self.manager = manager
        
                                      
                                 
                                                                               
        self.setFrameStyle(qt.QFrame.Panel | qt.QFrame.Plain)
        self.setLineWidth(1)

        self.contextpopups = {}
                                   

                                    
                              
                                                   
                                     
        
                                                     
        lv = self.listview = WorkspaceListView(self)
        
                                     
                                       
                          
        
        lv.setRootIsDecorated(True)

                                               
                                                                                              
        self.connect( lv, qt.SIGNAL("rightButtonPressed(QListViewItem *,const QPoint&,int)"), self._showContextMenu )
        self.connect( lv, qt.SIGNAL("doubleClicked(QListViewItem *, const QPoint &, int)"), self._itemDoubleClick )

                                                        
        lv.addColumn("Workspaces")
        lv.setColumnWidthMode(0, qt.QListView.Maximum)
                                                                                    

                         
        lv.setTreeStepSize(20)

                                                         
                                                 
                                                                
        self._workspace_items = []
        
    
    def sizeHint(self):
        return qt.QSize(70, 200)

    def resizeEvent (self, event ):
                                                                  
                                                           
                                                                 
                              
        self.listview.setColumnWidth(0,self.size().width()-7)
                                                                              
                                                                       
    
    def clearTree(self):
        """
        clear all the items in the tree
        """
        api.devlog("clearTree called")
        i = self.listview.firstChild()
        items_to_remove = []
        while i is not None:
                                                               
                             
                                                       
            items_to_remove.append(i)
            i = i.nextSibling()

        for i in items_to_remove:
            self.listview.takeItem(i)
    
    def customEvent(self, event):
        if event.type() in ():
            pass

    def loadAllWorkspaces(self):
        """
        Clear the tree and loads all workspaces defined in the workspace manager
        """
        self.clearTree()
        for name in self.manager.getWorkspacesNames():
            witem = WorkspaceListViewItem(self.listview, name=name, 
                                            is_active=self.manager.isActive(name),
                                            workspace_type=self.manager.getWorkspaceType(name))
            self._workspace_items.append(witem)

    def setDefaultWorkspace(self): 
        first_child = self.listview.firstChild()
        if first_child: 
            self._openWorkspace(first_child)
            
    def _itemDoubleClick(self, item, pos, val): 
        if not self.manager.isActive(item.name):
            self._openWorkspace(item)
        
    def _showContextMenu(self, item, pos, val):
        """Pop up a context menu when an item is right-clicked on the list view."""
                                                                                               
                                               
                                               
                                               
                              
        popup = qt.QPopupMenu(self)

        selected_items = self._getSelectedItems()

        if not selected_items:
                                                      
            popup.insertItem('Create Workspace', 100)
        else:
            if len(selected_items) == 1:
                if item.object.isActive():
                    popup.insertItem('Save', self._saveWorkspace)
                    popup.insertItem('Synchronize', self._syncWorkspace)
                    popup.insertItem('Close', 300)
                else:
                    popup.insertItem('Open', lambda: self._openWorkspace(item))
                    popup.insertItem('Delete', lambda: self._deleteWorkspace(item))
            
                popup.insertItem('Properties', lambda: self._showWorkspaceProperties(item))

            elif len(selected_items) > 1: 
                popup.insertItem('Delete', lambda: self._deleteWorkspaces(selected_items))
            else:
                api.devlog("ERROR: right click on an valid item (%r) which has a null object" % item)
            
        ret = popup.exec_loop(pos)
        
        api.devlog("contextMenuEvent WorkspaceItem - item: %s - ret %s" % (self.name, ret))
                                              

    def _getSelectedItems(self): 
        selected = []
        i = self.listview.firstChild()
        while i is not None:
            if i.isSelected(): selected.append(i)
            i = i.itemBelow()

        return selected


    def _deleteWorkspaces(self, items):
        for item in items:
            self._getMainApp().removeWorkspace(item.object.name)
        self.loadAllWorkspaces()

    def _deleteWorkspace(self, item):
        self._getMainApp().removeWorkspace(item.object.name)
        self.loadAllWorkspaces()
    
    def _openWorkspace(self, item): 
        api.devlog("Opening workspace %s selected on the Workspace Perspective" % item.objname)
        self._getMainApp().openWorkspace(item.objname) 
        self.loadAllWorkspaces()

    def _saveWorkspace(self):
        self._getMainApp().saveWorkspaces()
        
    def _syncWorkspace(self):
        self._getMainApp().syncWorkspaces()

    def _getMainApp(self):
        return self.parent().parent().getMainApp()

    def _showWorkspaceProperties(self, item):
        if item.object is not None:
            d = WorkspacePropertiesDialog(self, "Workspace Properties", workspace=item.object)
            d.exec_loop()
