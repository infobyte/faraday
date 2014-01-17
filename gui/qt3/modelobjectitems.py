'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import qt
import model.api as api
from edition import HostEditor, ServiceEditor, InterfaceEditor, GenericEditor, NoteEditor

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class ModelObjectListViewItem(qt.QListViewItem):
    """Item for displaying in the HostsBrowser."""
              

    def __init__(self, qtparent,  name = "", model_object=None):
        qt.QListViewItem.__init__(self, qtparent)
                                   
        self.setRenameEnabled(0, False)
        self.index = 0
        self.object = model_object
        self.name = name if name else model_object.getName()
        self._childs = {}
        self.setDragEnabled(False)
        self.setDropEnabled(False)
        self._setIcon()
        self._populateChildItems()
        self._checkVulns()
        self.editor = GenericEditor(None)

    def getChilds(self):
        return self._childs

    def getChild(self, key):
        return self._childs[key]

    def addChild(self, key, val):
        self._childs[key] = val

    def addHost(self, host):
        self.addChild(host.getID(), HostListViewItem(self, host.getName(), host))

    def addInterface(self, interface):
        self.addChild(interface.getID(), InterfaceListViewItem(self, interface.getName(), interface))

    def addInterfaces(self):
        for interface in self.object.getAllInterfaces():
            self.addInterface(interface)

    def addApplication(self, application):
        self.addChild(application.getID(), ApplicationListViewItem(self, application.getName(), application))

    def addApplications(self):
        for application in self.object.getAllApplications():
            self.addApplication(application)

    def addService(self, service):
        self.addChild(service.getID(), ServiceListViewItem(self, service.getName(), service))

    def addServices(self):
        for service in self.object.getAllServices():
            self.addService(service)

    def addNote(self, note):
        self.addChild(note.getID(), NoteListViewItem(self, note.name, note))

    def addNotes(self):
        for note in self.object.getNotes():
            self.addNote(note)

    def addVuln(self, vuln):
        if vuln.class_signature == "VulnerabilityWeb":
            self.addChild(vuln.getID(), VulnWebListViewItem(self, vuln.name, vuln))
        else:
            self.addChild(vuln.getID(), VulnListViewItem(self, vuln.name, vuln))

    def addVulns(self):
        for vuln in self.object.getVulns():
            self.addVuln(vuln)

    def addCred(self, cred):
        self.addChild(cred.getID(), CredListViewItem(self, cred.name, cred))

    def addCreds(self):
        for cred in self.object.getCreds():
            self.addCred(cred)

    def clear(self):
        i = self.firstChild()
        items_to_remove = []
        while i is not None:
            items_to_remove.append(i)
            i = i.nextSibling()
        for i in items_to_remove:
            item = i
            i.clear()
            del i
            try:
                self.takeItem(item)
            except:
                pass
        self._childs.clear()

    def getContextMenu(self):
        pass

    def _setIcon(self):
                                                                            
                                 
                                                                
        owned = self.object.isOwned() if self.object is not None else False
        icon_name = "Tree%sOwned-20.png" % self.type if owned else "Tree%s-20.png" % self.type
        
                                      
        if self.type == "Service" and not owned:
            if self.object.getStatus() !="open":
                icon_name = "TreeOff%s-20.png" % self.type
        
        
        icon_path = os.path.join(CONF.getIconsPath(), icon_name)
        
        pm = qt.QPixmap(icon_path)
        self.setPixmap(0, pm)
        
    def _checkVulns(self):
        """
        Verifies if the item has vulnerabilities
        and shows it different with details
        """
        if self.object is not None:
            madd=[]
            vulns = self.object.getVulns()
            if vulns:
                madd.append("v:"+str(len(vulns)))
            notes = self.object.getNotes()
            if notes:
                madd.append("n:"+str(len(notes)))
            creds = self.object.getCreds()
            if creds:
                madd.append("c:"+str(len(creds)))
            if madd:
                newname=""
                if self.type == "Service":
                    newname = "(%s/%s) %s [%s]"  % (", ".join(["%s" % p for p in self.object.getPorts()]),
                                         self.object.getProtocol(), self.object.name, ",".join(madd))
                else:
                    newname = "%s [%s]" % (self.object.name, ",".join(madd))
                self.name = newname
                
    
    
    def _populateChildItems(self):
        """
        this creates new children items if needed
        to populate the tree
        depending on the item type this can create different items
        """
        pass

                                                            
                                                                 
                                                              
    def dragEntered(self):
        pass

    def dragLeft(self):
        pass

    def dropped(self, e):
                               
        pass

    def setText(self, col, text):
        """Update name of widget if rename is called."""
                               
        if col == 0:
            self.name = text

        qt.QListViewItem.setText(self, col, text)

    def rename(self):
        """Rename the listviewitem."""
        self.startRename(0)

                                                            
               
    def compare(self, i, col, ascending):
        """
        #Always sort according to the index value.

        a = [-1, 1][ascending]

        if self.index < i.index:
            return -1*a
        elif self.index > i.index:
            return 1*a
        else:
            return 0
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
    
    def getModelObject(self):
        return self.object

    def setModelObject(self, model_object):
        self.object = model_object

                                         
                                                                        
                        

    def getEditor(self):
        return self.editor

                                                                                
class RootListViewItem(ModelObjectListViewItem):
    type = "Root"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setOpen(True)

class WorkspaceListViewItem(ModelObjectListViewItem):
    type = "Workspace"
    def __init__(self, qtparent, model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, model_object.name, model_object)
        self.setOpen(True)
        self.nconflicts = 0

    def _checkVulns(self):
        pass

    def _setIcon(self):
        
        if self.object.__class__.__name__ == "WorkspaceOnCouch":
            icon_name = "TreeRoot-20.png"
        else:
            icon_name = "TreeOffRoot-20.png"
        icon_path = os.path.join(CONF.getIconsPath(), icon_name)
        pm = qt.QPixmap(icon_path)
        self.setPixmap(0, pm)

    def updateName(self, nconflicts):
        self.nconflicts += nconflicts
        if self.nconflicts:
            self.name = "%s (%s)" % (self.getModelObject().name, self.nconflicts)
        else:
            self.name = "%s" % (self.getModelObject().name)

                                                                                
class CategoryListViewItem(ModelObjectListViewItem):
    type = "Category"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setDropEnabled(True)                                     
        self.setOpen(True)

    def selectByWord(self, word):
        for host_item in self.getChilds().values():
            if host_item.text(0).encode('utf8').strip() == word.strip():
                self.setSelected(True)
                break

                                                                                
class HostListViewItem(ModelObjectListViewItem):
    type = "Host"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
                                                     
                                                    
        self.setDragEnabled(True)
        self.setOpen(True)
        self.editor = HostEditor(self.object)

    def _populateChildItems(self):
                                                                              
                                                                                  
        
                                                                                          
                                                    
                                     
                                                               
        self.addInterfaces()
                           

                                                
                         
                                                              
    
    def _clearHost(self):
        self.clear()
                                               
                                             
                               
                              
                          

    def _clearServicesFromApplications(self):
        for item in self._childs:
            if item.name == "Applications":
                for app in item._childs:
                    app.clearServices()
    
    def _addServicesToApplications(self):
        for item in self._childs:
            if item.name == "Applications":
                for app in item._childs:
                    app._populateChildItems()
    
    def _clearServicesFromInterfaces(self):
        for item in self._childs:
            if item.name == "Interfaces":
                for interface in item._childs:
                    interface.clearServices()
    
    def _addServicesToInterfaces(self):
        for item in self._childs:
            if item.name == "Interfaces":
                for interface in item._childs:
                    interface._populateChildItems()
    
    def _setIcon(self):
        owned = self.object.isOwned() if self.object is not None else False
        if owned:
            icon_name = "User%sOwned.png" % self.type
        else:
            _oper = self.object.getOS()
            if "LINUX" in _oper.upper():
                icon_name = "tux.png"    
            elif "WINDOWS" in _oper.upper():
                icon_name = "windows.png"    
            elif "APPLE" in _oper.upper():
                icon_name = "Apple.png"
            elif "MAC" in _oper.upper():
                icon_name = "Apple.png"
            elif "CISCO" in _oper.upper():
                icon_name = "Cisco.png"
            elif "IOS" in _oper.upper():
                icon_name = "Cisco.png"                
            elif "LINKSYS" in _oper.upper():
                icon_name = "Router.png"
            elif "ROUTER" in _oper.upper():
                icon_name = "Router.png"
            else:
                icon_name = "Tree%s-20.png" % self.type
            
            
        icon_path = os.path.join(CONF.getIconsPath(), icon_name)
        pm = qt.QPixmap(icon_path)
        self.setPixmap(0, pm)


                                                                                
class InterfaceListViewItem(ModelObjectListViewItem):
    type = "Interface"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.editor = InterfaceEditor(self.object)
        self.setOpen(True)

    def _populateChildItems(self):
                                                 
        self.addServices()
    
    def clearServices(self):
        for s in self._childs:
            self.takeItem(s)
                  
        self._childs = []
        
                                                                                
class ApplicationListViewItem(ModelObjectListViewItem):
    type = "Application"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)

    def _populateChildItems(self):
                                                   
        self.addServices()
    
    def clearServices(self):
        for s in self._childs:
            self.takeItem(s)
                  
        self._childs = []

                                                                                
class ServiceListViewItem(ModelObjectListViewItem):
    type = "Service"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.name = "(%s/%s) %s"  % (", ".join(["%s" % p for p in self.object.getPorts()]),
                                     self.object.getProtocol(), self.object.name )
        self.editor = ServiceEditor(self.object)
        self._checkVulns()

                                                                                

class NoteRootItem(RootListViewItem):
    type = "NoteRoot"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setOpen(True)
        self.name = self.object.name

    def _setIcon(self):
        pass

class NoteListViewItem(ModelObjectListViewItem):
    type = "Note"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
                                   
                                          
        self.setOpen(True)

    def _populateChildItems(self):
        self.addNotes()
    
    def clearNotes(self):
        for s in self._childs:
            self.takeItem(s)
                  
        self._childs = []

class VulnRootItem(RootListViewItem):
    type = "VulnRoot"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setOpen(True)
        self.name = self.object.name

    def _setIcon(self):
        pass

class VulnListViewItem(ModelObjectListViewItem):
    type = "Vuln"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
                                   
                                          
        self.setOpen(True)

    def _populateChildItems(self):
        self.addVulns()
    
    def clearVulns(self):
        for s in self._childs:
            self.takeItem(s)
                  
        self._childs = []

class VulnWebListViewItem(VulnListViewItem):
    type = "VulnWeb"
    def __init__(self, qtparent, name = "", model_object=None):
        VulnListViewItem.__init__(self, qtparent, name, model_object)

class CredRootItem(RootListViewItem):
    type = "CredRoot"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setOpen(True)
        self.name = self.object.name

    def _setIcon(self):
        pass

class CredListViewItem(ModelObjectListViewItem):
    type = "Cred"
    def __init__(self, qtparent, name = "", model_object=None):
        ModelObjectListViewItem.__init__(self, qtparent, name, model_object)
        self.setOpen(True)
        self.name = "%s: %s" % (model_object.username, model_object.password)

    def _populateChildItems(self):
        self.addCreds()
    
    def clearVulns(self):
        for s in self._childs:
            self.takeItem(s)
                  
        self._childs = []

