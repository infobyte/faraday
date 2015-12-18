'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import qt
from threading import Lock
from gui.qt3.modelobjectitems import *
import model.api as api
import model.guiapi as guiapi
import re as re
from gui.qt3.dialogs import NewVulnDialog, ConflictResolutionDialog, MessageDialog, NotesDialog, VulnsDialog, CredsDialog
from gui.qt3.customevents import *
from gui.qt3.dialogs import WorkspacePropertiesDialog
from gui.qt3.edition import EditionTable, NewServiceDialog, NewHostDialog, NewInterfaceDialog, NewCredDialog, NewNoteDialog

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

from whoosh.index import create_in
from whoosh.fields import *


class PropertyItem(qt.QListViewItem):
                                                                
                         
    """Item for displaying a preferences-set in HostsBrowser."""
    def __init__(self, settings, number, parent):
        """_plugin_settings is the _plugin_settings class to work for
        parent is the parent ListViewItem (of type ModelObjectListViewItem)
        """
        qt.QListViewItem.__init__(self, parent)
        self.settings = settings
        self.parent = parent
        self.widget = None
        self.setText(0, settings.name)
        self.setText(1, 'setting')
        self.index = number

    def compare(self, i, col, ascending):
        """Always sort according to the index value."""

        a = [-1, 1][ascending]

        if self.index < i.index:
            return -1*a
        elif self.index > i.index:
            return 1*a
        else:
            return 0


class ModelObjectListView(qt.QListView):
    """
    List view for hosts
    It allows Drag and Drop (TODO)
    """
    def __init__(self, parent=None):
        qt.QListView.__init__(self, parent)
        self.setSelectionMode(qt.QListView.Extended)

                          
                                                                    
                                                                           
                                                
                     

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

    def sizeHint(self):
        return qt.QSize(500, 800)


class SaveButton(qt.QPushButton):
    def __init__(self, parent, callback):
        qt.QPushButton.__init__(self, "Save", parent)
        parent.connect(self, qt.SIGNAL('clicked()'), callback)
        self.setMaximumSize(qt.QSize(75, 25))


class HostsBrowser(qt.QVBox):
    """Tree view to display Hosts"""

    def __init__(self, parent, model_controller, caption):
        qt.QVBox.__init__(self, parent)

        self._model_controller = model_controller

        self.modelUpdateTimer = qt.QTimer(self)
       
        self.__pendingModelObjectRedraws = []

        self.reindex_flag_lock = Lock()
        self.reindex_flag = False

        self.connect( self.modelUpdateTimer, qt.SIGNAL("timeout()"), self._modelObjectViewUpdater)
                                        
        self.modelUpdateTimer.start( 1000  , False)
                                                                                 

        self.setName(caption) if caption else self.setName("")

        self.setFrameStyle(qt.QFrame.Panel | qt.QFrame.Plain)
        self.setLineWidth(0)

        self._host_items = {}

                                                                                                   
        self._category_items = {}

                                                                                                
                                                                        
        self._category_tree = {}

        self.contextpopups = {}
        self._setupContextPopups()

        self.contextdispatchers = {}

                       
        self._filter = ""
        self.ix = None

        self._setupContextDispatchers()

        split = qt.QSplitter(self)
        split.setOrientation(qt.QSplitter.Vertical)

        lv = self.listview = ModelObjectListView(split)
                                     
                                       
                                         
        lv.setRootIsDecorated(True)

                                               
        self.connect( lv, qt.SIGNAL("selectionChanged()"), self._itemSelected )
        self.connect( lv, qt.SIGNAL("rightButtonPressed(QListViewItem *,const QPoint&,int)"), self._showContextMenu )
                                                        
        lv.addColumn("Hosts")
        lv.setColumnWidthMode(0,qt.QListView.Maximum)
                                                                                    

                         
        lv.setTreeStepSize(20)

                                                                           
                                                                                                  
                                                                
                                                             
        self.rootitem = None

                                            
               

                                                                           
        self.details_table = EditionTable(split)
        hbox = qt.QHBox(self)
        self.object_label = qt.QLabel("", hbox)
        self.object_label.setMinimumSize(qt.QSize(50, 25))
        self.save_button = SaveButton(hbox, self._item_save)
        self._save_callback = None

        self.prefchilds = []

                              
                                                       

    def load(self, workspace, workspace_type):
        self.rootitem = WorkspaceListViewItem(self.listview, workspace, workspace_type)
        self.listview.setSelected(self.rootitem, True)

    def update(self, hosts):
        self.clearTree()
        self.redrawTree(hosts)
                                         
    def sizeHint(self):
        """Returns recommended size of dialog."""
        return qt.QSize(70, 200)

    def resizeEvent (self, event ):
                                                                  
                                                           
                                                                 
                              
        self.listview.setColumnWidth(0,self.size().width()-7)
                                                                              
                                                                       

    def clearTree(self):
        """
        clear the complete host tree
        """
        self._clearBranch(self.rootitem)
        self._host_items.clear()

    def _clearBranch(self, root):
        """
        clear a branch based on the root provided.
        """
        if root is not None:
            i = root.firstChild()
            items_to_remove = []
            while i is not None:
                items_to_remove.append(i)
                i = i.nextSibling()

            for i in items_to_remove:
                if i.type == "Category":
                    self._delCategory(i.name)
                elif i.type == "Host":
                    category_item = i.parent()
                    self._delHostFromCategory(i.object, category_item.name)

    def redrawTree(self, hosts):
        dialog = qt.QProgressDialog(self, "Loading workspace...", True)
        dialog.setCaption("Please wait")
        dialog.setLabelText("Loading workspace...")
        dialog.setTotalSteps(len(hosts) + 1)
        i = 1
        for host in hosts:
            dialog.setProgress(i)
            category = host.getCurrentCategory()
            self._addCategory(category)
            self._addHostToCategory(host, category)
            i += 1
        for ci in self._category_items.values():
            ci.setOpen(True)

        self.createIndex()
        dialog.setProgress(i)
        self.filterTree(self._filter)
        # we need to make sure that the dialog is closed
        rem = dialog.totalSteps() - i
        if rem > 0:
            dialog.setProgress(i + rem)

    def setReindex(self):
        self.reindex_flag_lock.acquire()
        if not self.reindex_flag:
            self.reindex_flag = True
        self.reindex_flag_lock.release()

    def reindex(self):
        self.reindex_flag_lock.acquire()
        if self.reindex_flag:
            self.createIndex()
            self.reindex_flag = False
        self.reindex_flag_lock.release()

    def filterTree(self, mfilter=""):
        self.reindex()
        hosts=[]
        viewall=False
        self._filter=mfilter

        for k in self._host_items.keys():
            hosts.append(self._host_items[k].object)

        if self._filter:
            hosts=self._filterHost(hosts)
        else:
            viewall=True
            hosts=[]

                                
                    

        for k in self._host_items.keys():
                                                  
            if (self._host_items[k].object.name in hosts) or viewall==True:
                self._host_items[k].setVisible(True)
            else:
                self._host_items[k].setVisible(False)


    def _filterHost(self,hosts):
                                  

        from whoosh.qparser import QueryParser
        with self.ix.searcher() as searcher:
            query = QueryParser("ip", self.ix.schema).parse(self._filter)
            results = searcher.search(query, limit=None)
                           
                        
                          
            hostv={}
            for r in results:
                hostv[r['ip']]=1

        return hostv

    def createIndex(self):
        hosts = self._model_controller.getAllHosts()
        schema = Schema(ip=TEXT(stored=True),
                        hostname=TEXT(stored=True),
                        mac=TEXT(stored=True),
                        os=TEXT(stored=True),
                        port=TEXT(stored=True),
                        srvname=TEXT(stored=True),
                        srvstatus=TEXT(stored=True),
                        vulnn=TEXT(stored=True),
                        namen=TEXT(stored=True),
                        owned=BOOLEAN,
                        cred=BOOLEAN,
                        vuln=BOOLEAN,
                        note=BOOLEAN)

        indexdir=CONF.getDataPath() + "/indexdir"
        if not os.path.exists(indexdir):
            os.mkdir(indexdir)

        self.ix = create_in(indexdir, schema)
        for host in hosts:
            self.indexHost(host)

    def indexHost(self, host):
        writer = self.ix.writer()
        writer.add_document(ip=unicode(host.name), os=unicode(host.getOS()),
                            owned=host.isOwned(),
                            vuln=True if host.vulnsCount() > 0 else False,
                            note=True if len(host.getNotes()) > 0 else False)

        for i in host.getAllInterfaces():
            for h in i._hostnames:
                writer.add_document(ip=unicode(host.name),
                                    hostname=unicode(h),
                                    mac=unicode(i.getMAC()))

        for v in host.getVulns():
            writer.add_document(ip=unicode(host.name), vulnn=unicode(v.name))

        for i in host.getAllInterfaces():
            for s in i.getAllServices():
                for v in s.getVulns():
                    writer.add_document(ip=unicode(host.name),
                                        vulnn=unicode(v.name),
                                        srvname=unicode(s.getName()))
                for p in s.getPorts():
                    writer.add_document(
                        ip=unicode(host.name),
                        port=unicode(str(p)),
                        owned=s.isOwned(),
                        vuln=True if s.vulnsCount() > 0 else False,
                        note=True if len(s.getNotes()) > 0 else False,
                        cred=True if s.credsCount() > 0 else False,
                        srvname=unicode(s.getName()),
                        srvstatus=unicode(s.getStatus()))
        writer.commit()

    def removeIndexHost(self, host):
        writer = self.ix.writer()
        writer.delete_by_term('ip', host.name)
        writer.commit()

    def selectWord(self, word):
        for k in self._host_items:
            host_item = self._host_items[k]
            if host_item.text(0).encode('utf8').strip() == word.strip():
                self.listview.setSelected(host_item, True)
                self.listview.ensureItemVisible(host_item)
                break
            else:
                for i in host_item.object.getAllInterfaces():
                    if i.ipv4['address'] == word.strip():
                        self.listview.setSelected(host_item, True)
                        self.listview.ensureItemVisible(host_item)
                        break
                    elif i.ipv6['address'] == word.strip():
                        self.listview.setSelected(host_item, True)
                        self.listview.ensureItemVisible(host_item)
                        break
                    else:
                        for h in i.getHostnames():
                            if h == word.strip():
                                self.listview.setSelected(host_item, True)
                                self.listview.ensureItemVisible(host_item)
                                break

    def workspaceChanged(self, workspace, workspace_type):
        if self.rootitem:
            root = self.rootitem
            self.listview.takeItem(root)
            del root
        self.clearTree()
        self.load(workspace,workspace_type)

    def updateWorkspaceName(self, nconflicts):
        self.rootitem.updateName(nconflicts)

    def _resolveConflicts(self, item):
        guiapi.resolveConflicts()

    def showResolveConflictDialog(self, conflicts):
        if len(conflicts):
            dialog = ConflictResolutionDialog(conflicts)
            dialog.exec_loop()

    def _item_save(self):
                                                                 
                         
        if self._save_callback is not None:
            self._save_callback()

    def setSaveCallback(self, callback):
        self._save_callback = callback

    def _itemSelected(self, item=False):
        """
        this is called when a list view item is selected
        """
                           
        i = self.listview.firstChild()
        self.items_selected=[]
        self.items_type={'Host': 0, 'Workspace': 0, 'Service':0,
                         'Interface':0, 'Application':0,'Category_General':0
                         ,'Category_Applications':0,'Category_Interfaces':0}
        while i is not None:
            if i.isSelected():

                if i.type=="Category":
                    self.items_type[i.type+"_"+i.name] =self.items_type[i.type+"_"+i.name]+1
                else:
                    self.items_type[i.type] =self.items_type[i.type]+1

                self.items_selected.append(i)
            i = i.itemBelow()
            mtype={'Host': 0, 'Workspace': 0, 'Service':0, 'Interface':0, 'Application':0,'Category':0}

        self.itemselected = self.listview.currentItem()

                                                                                
        self.details_table.clear()
        editor = self.itemselected.getEditor()
        editor.fillEditionTable(self.details_table)
        self.setSaveCallback(editor.save)

    def getItemSelected(self):
        return self.itemselected

    def _addCategory(self, category):
        if category not in self._category_tree:
            self._category_tree[category] = []
            ref = CategoryListViewItem(self.rootitem, category)
            self._category_items[category] = ref
        else:
            ref = self._getCategoryListViewItem(category)
        return ref

    def _addHost(self, host):
        category = host.getCurrentCategory()
        self._addCategory(category)
        self._addHostToCategory(host, category)
        #self.removeIndexHost(host)
        #self.indexHost(host)

    def _removeHost(self, host_id):
        item = self._host_items.get(host_id, None)
        if host_id in self._host_items:
            del self._host_items[host_id]
        for category in self._category_tree.keys():
            if host_id in self._category_tree.get(category):
                self._category_tree[category].remove(host_id)
                category_item = self._getCategoryListViewItem(category)
                try:
                    category_item.takeItem(item)
                except Exception:
                    api.devlog("Exception taking item from category")

    def _editHost(self, host):
        self._removeHost(host.getID())
        self._addHost(host)

    def _addHostToCategory(self, host, category):
        category_item = self._addCategory(category)
        self._host_items[host.getID()] = HostListViewItem(category_item, host.name, host)
        self._category_tree[category].append(host.getID())

    def _delHostFromCategory(self, host, category):
        id = host.getID()
        item = self._host_items.get(id, None)
        if id in self._host_items:
            del self._host_items[id]
        if category in self._category_tree:
            if id in self._category_tree[category]:
                self._category_tree[category].remove(id)
                category_item = self._getCategoryListViewItem(category)
                api.devlog("_delHostFromCategory: about to call takeItem for category %s" % category)
                try:
                    category_item.takeItem(item)
                except Exception:
                    pass
                api.devlog("_delHostFromCategory: after takeItem")

    def _getCategoryListViewItem(self, category):
        return self._category_items.get(category, None)

    def _delCategory(self, category, recursive=False):
        if category in self._category_tree:
            if recursive:                                              
                for id in self._category_tree:
                    host_item = self._getHostListViewItem(id)
                    if host_item is not None:
                        self._delHostFromCategory(host_item.object, category)
            else:
                                                                                   
                                               
                for id in self._category_tree:
                    host_item = self._getHostListViewItem(id)
                    if host_item is not None:
                        self._moveHostToCategory(host_item.object, CONF.getDefaultCategory())

                del self._category_tree[category]
                item = self._category_items[category]
                del self._category_items[category]
                self.rootitem.takeItem(item)

    def _getHostListViewItem(self, id):
        return self._host_items.get(id, None)

    def _showContextMenu(self, item, pos, val):
        """Pop up a context menu when an item is clicked on the list view."""
        ret = None

        if item is not None:                           

                                  
                       
                                                                                                                                                            
            if self.items_type['Interface']:
                if (self.items_type['Category_General'] or self.items_type['Workspace']):
                    popname="CategoryWorkspace_Interface"
                elif (self.items_type['Host'] or self.items_type['Service']):
                    popname="ServiceHost_Interface"
                else:
                    popname=item.type

            elif (self.items_type['Host'] or self.items_type['Service']):
                if (self.items_type['Category_General'] or self.items_type['Workspace']):
                    popname="CategoryWorkspace_ServiceHost"
                elif (self.items_type['Host'] and self.items_type['Service']):
                    popname="Service_Host"
                else:
                    if item.type is "Category":
                        popname="Host"
                    else:
                        popname=item.type
            else:
                                   
                if item.type is "Category":
                    popname=item.type + "_" + item.name
                else:
                    popname=item.type

            ret = self.contextpopups[popname].exec_loop(pos)

            if ret in self.contextdispatchers:
                self.contextdispatchers[ret](item)
                  
                                                                         

            api.devlog("contextMenuEvent - item: %s - ret %s" % (self.name, ret))

              

    def _newHost(self, item):
        api.devlog("newHost")
        dialog = NewHostDialog(self, self._newHostCallback)
        dialog.exec_loop()

    def _newHostCallback(self, name, os):
        if name:
                                          
            guiapi.createAndAddHost(name, os=os)

    def _delHost(self,item):
        api.devlog("delHost")
        if item is not None and item.object is not None:                                                  
            dialog = MessageDialog(self,title="Host delete",callback=self._delSelectedCallback)
            dialog.exec_loop()

    def _delHostCallback(self, item):
        api.devlog("delcallbackHost %s " % (item.object.name))
        guiapi.delHost(item.object.getID())

    def _newInterface(self, item):
        api.devlog("newInterface")
        dialog = NewInterfaceDialog(self, self._newInterfaceCallback)
        dialog.exec_loop()

    def _newInterfaceCallback(self, name, ipv4_address, ipv6_address):
        if name and (ipv4_address or ipv6_address):
            for i in self.items_selected:
                host_id = i.object.getID()
                guiapi.createAndAddInterface(host_id, name, ipv4_address=ipv4_address, ipv6_address=ipv6_address)

    def _delInterface(self,item):
        api.devlog("delInterface")
        if item is not None and item.object is not None:                                                  
            dialog = MessageDialog(self,title="Interface delete",callback=self._delSelectedCallback)
            dialog.exec_loop()

    def _delInterfaceCallback(self, item):
        api.devlog("delcallbackInterface %s " % (item.object.name))
        _parent=item.object.getParent()
        guiapi.delInterface(_parent.getID(), item.object.getID())

    def _newService(self,item):
        api.devlog("newService")
        dialog = NewServiceDialog(self, self._newServiceSelectedCallback)
        dialog.exec_loop()

    def _newServiceSelectedCallback(self, name, protocol, ports):
        if name and protocol and ports:
            for i in self.items_selected:
                if i.type == "Interface":
                    interface_id = i.object.getID()
                    host_id = i.object.getParent().getID()
                    guiapi.createAndAddServiceToInterface(host_id, interface_id , name, protocol=protocol, ports=ports)

    def _delService(self,item):
        if item is not None and item.object is not None:                                                  
            dialog = MessageDialog(self,title="Delete Item(s)",callback=self._delSelectedCallback)
            dialog.exec_loop()

    def _delServiceCallback(self, item):
        api.devlog("delcallbackService %s " % (item.name))
        _object=item.object
        _host=_object.getParent()
        guiapi.delServiceFromHost(_host.getID(), _object.getID())

    def _delSelectedCallback(self,item):

        for i in self.items_selected:
            if i.type == "Host":
                api.devlog("delcallbackHost %s " % (i.object.name))
                guiapi.delHost(i.object.getID())
            elif i.type == "Application":
                api.devlog("delcallbackApplication %s " % (i.object.name))
                _parent=i.object.getParent()
                _object=i.object
                guiapi.delApplication(_parent.getID(),_object.getID())
            elif i.type == "Interface":
                api.devlog("delcallbackInterface %s " % (i.object.name))
                _parent=i.object.getParent()
                _object=i.object
                guiapi.delInterface(_parent.getID(), _object.getID())
            elif i.type == "Service":
                api.devlog("delcallbackService %s " % (i.name))
                _object=i.object
                parent_interface = self._getParentForType(i, "Interface").object
                parent_host = self._getParentForType(i, "Host").object
                guiapi.delServiceFromInterface(parent_host.getID(), parent_interface.getID(), _object.getID())
                                                       
        self.listview.setCurrentItem(self.rootitem)
        self._itemSelected()

    def _getParentForType(self, obj, obj_type):
        parent = obj.parent()
        if obj_type == parent.type:
            return parent
        else:
            return self._getParentForType(parent, obj_type)

    def _newCategory(self,item):
        api.devlog("newCategory")

    def _renCategory(self,item):
        api.devlog("renCategory")

    def _delCategorymenu(self,item):
        api.devlog("delCategorymenu")
        if item is not None:                                                  
            dialog = MessageDialog(self,title="Category delete",callback=self._delCategoryCallback,item=item)
            dialog.exec_loop()

    def _delCategoryCallback(self, item):
        api.devlog("delcallbackCategory %s " % (item.name))

    def _newVuln(self, item):
        api.devlog("newVuln")
        if item is not None and item.object is not None:
            vuln_web_enabled = False
            if item.object.class_signature == "Service":
                vuln_web_enabled = True
            dialog = NewVulnDialog(
                self,
                callback=self._newVulnSelectedCallback,
                vuln_web_enabled=vuln_web_enabled)
            dialog.exec_loop()

    def _newVulnSelectedCallback(self, *args):
        callback = guiapi.createAndAddVuln
        if args[0]:
            # vuln web
            callback = guiapi.createAndAddVulnWeb

        for i in self.items_selected:
            callback(i.object, *args[1:])

    def _listVulns(self,item):
        if item is not None and item.object is not None:
            dialog = VulnsDialog(parent=self, model_object=item.object)
            dialog.exec_loop()

    def _listVulnsCvs(self,item):
        vulns=""
        hosts=[]
        for k in self._host_items.keys():
            hosts.append(self._host_items[k].object)

        filename =  qt.QFileDialog.getSaveFileName(
                    "/tmp",
                    "Vulnerability CVS  (*.csv)",
                    None,
                    "save file dialog",
                    "Choose a file to save the vulns" )
        from exporters.tofile import CSVVulnStatusReport
        CSVVulnStatusReport(path = filename, 
                            modelobjects = hosts).createCSVVulnStatusReport() 

    def _importVulnsCvs(self,item):
        filename =  qt.QFileDialog.getOpenFileName(
                    CONF.getDefaultTempPath(),
                    "Csv vulnerability file  (*.*)",
                    None,
                    "open file dialog",
                    "Choose a vulnerability file" );
        
        if os.path.isfile(filename):
            with open(filename) as f:
                data = f.read()
            f.close()

            for l in data.split("\n"):
                api.devlog(l)
                if re.search("^#",l):
                    api.devlog("ERROR FILE")
                    continue
                
                d = l.split("|")
                
                if len(d) <=8:
                    api.log("Error vuln line: ("+l+")" )
                else:
                    self._newVulnImport(d[1],d[2],d[3],d[4],d[5],d[6],d[7])

    def _newVulnImport(self,ip,port,protocol,name,desc,severity,type):
        if port == "": #vuln host
            h_id = guiapi.createAndAddHost(ip)
            v_id = guiapi.createAndAddVulnToHost(h_id, name, desc, [],severity)
        else: #vuln port
            h_id = guiapi.createAndAddHost(ip)
            if self._isIPV4(ip):
                i_id = guiapi.createAndAddInterface(h_id,ip,ipv4_address=ip)
            else:
                i_id = guiapi.createAndAddInterface(h_id,ip,ipv6_address=ip)
            s_id = guiapi.createAndAddServiceToInterface(h_id,i_id,port,protocol,ports=[port])
            if type == "2":
                v_id = guiapi.createAndAddVulnWebToService(h_id,s_id, name, desc, [], severity, "/", "/")
            else:                
                v_id = guiapi.createAndAddVulnToService(h_id,s_id, name, desc, [],severity)

        api.devlog("type:" + type)
                                   
    def _isIPV4(self, ip):
        if len(ip.split(".")) == 4:
            return True
        else:
            return False

    def _listNotes(self, item):
        if item is not None and item.object is not None:                                                  
            dialog = NotesDialog(parent=self, model_object=item.object)
            dialog.exec_loop()

    def _newNote(self, item):
        if item is not None and item.object is not None:                                                  
            dialog = NewNoteDialog(self, callback=self._newNoteSelectedCallback)
            dialog.exec_loop()

    def _newNoteSelectedCallback(self, name, text):
        for i in self.items_selected:
            if i.type == "Host":
                api.devlog("newNotecallbackHost %s " % (i.object.name))
                guiapi.createAndAddNoteToHost(i.object.getID(), name, text)
            elif i.type == "Application":
                _parent=i.object.getParent()
                api.devlog("newNotecallbackApplication %s " % (i.object.name))
                guiapi.createAndAddNoteToApplication(_parent.getID(), i.object.getID(), name, text)
            elif i.type == "Interface":
                _parent=i.object.getParent()
                api.devlog("newNotecallbackInterface %s " % (i.object.name))
                guiapi.createAndAddNoteToInterface(_parent.getID(), i.object.getID(), name, text)
            elif i.type == "Service":
                _parent=i.object.getParent().getParent()
                api.devlog("newNotecallbackService %s " % (i.name))
                guiapi.createAndAddNoteToService(_parent.getID(), i.object.getID(), name, text)

    def _listCreds(self, item):
        if item is not None and item.object is not None:
            dialog = CredsDialog(parent=self, model_object=item.object)
            dialog.exec_loop()

    def _newCred(self, item):
        api.devlog("newCred")
        dialog = NewCredDialog(self, self._newCredSelectedCallback)
        dialog.exec_loop()

    def _importCreds(self, item):
        filename =  qt.QFileDialog.getOpenFileName(
                    CONF.getDefaultTempPath(),
                    "Csv user,pass or user:pass  (*.*)",
                    None,
                    "open file dialog",
                    "Choose a password file" );
        
        if os.path.isfile(filename):
            with open(filename) as f:
                data = f.read()
            f.close()

            for l in data.split():
                api.devlog(l)
                if re.search("^#",l):
                    api.devlog("ERROR FILE")
                    continue
                
                d = l.split(",")
                if len(d)<=1:
                    d = l.split(":")
                
                api.devlog(d)
                if len(d) <=1:
                    api.devlog("Error password line: ("+l+")" )
                else:
                    self._newCredSelectedCallback(d[0],d[1])

    def _newCredSelectedCallback(self,username,password):

        for i in self.items_selected:
            if i.type in ['Host','Service']:
                guiapi.createAndAddCred(i.object,username,password)

    def _showWorkspaceProperties(self, item):
        if item.object is not None:
            d = WorkspacePropertiesDialog(self, "Workspace Properties", workspace=item.object)
            d.exec_loop()

    def _modelObjectViewUpdater(self): 
        if len(self.__pendingModelObjectRedraws):
            self.update(self.__pendingModelObjectRedraws.pop().hosts)
            self.__pendingModelObjectRedraws[:] = []

    def customEvent(self, event):
        if event.type() == UPDATEMODEL_ID:
            self.__pendingModelObjectRedraws.append(event)

        elif event.type() == RENAMEHOSTSROOT_ID:
            self.renameRootItem(event.name)

        elif event.type() == DIFFHOSTS_ID:
            self._diffHosts(event.old_host, event.new_host)

        elif event.type() == CLEARHOSTS_ID:
            self.clearTree()

        elif event.type() == WORKSPACE_CHANGED:
            self.workspaceChanged(event.workspace, event.workspace_type)

        elif event.type() == CONFLICT_UPDATE:
            self.updateWorkspaceName(event.nconflicts)

        elif event.type() == RESOLVECONFLICTS_ID:
            self.showResolveConflictDialog(event.conflicts)

        elif event.type() == ADDHOST:
            self._addHost(event.host)
            self.setReindex()

        elif event.type() == DELHOST:
            self._removeHost(event.host_id)
            self.setReindex()

        elif event.type() == EDITHOST:
            self._editHost(event.host)
            self.setReindex()


    def _setupContextPopups(self):
        """
        Configures a context popup menu for each kind of item shown in the tree.
        This is done because different options may be needed for each item
        """
                         
        popup = qt.QPopupMenu(self)
                                      
                                             
                                            
        popup.insertSeparator()
        popup.insertItem('Resolve Conflicts', 303)
        popup.insertItem('Save Vulns CSV', 402)
        popup.insertItem('Import Vulns CSV', 403)
                                
                                              
        popup.insertSeparator()
        popup.insertItem('Add Host', 800)

        self.contextpopups["Workspace"] = popup

        self.contextpopups["Category_General"] = self.contextpopups["Workspace"]

                                
        popup = qt.QPopupMenu(self)
                                                  
                                
                                       

        self.contextpopups["Category_Applications"] = popup

                              
        popup = qt.QPopupMenu(self)
        popup.insertItem('Add Interfaces', 600)
                                
                                       

        self.contextpopups["Category_Interfaces"] = popup

                        
                                     
                                                     
                                 
                                              
                                 
                                                   
                                                      
                                 
                                           
                                             
                                 
                                        

                                                   

               
        popup = qt.QPopupMenu(self)
        popup.insertItem('Delete Host', 802)
        popup.insertSeparator()
        popup.insertItem('Add Interface', 600)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability',400)
        popup.insertItem('List Vulnerabilities',401)
        popup.insertSeparator()
        popup.insertItem('New note', 500)
        popup.insertItem('Show notes', 501)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Show Credentials', 551)
        popup.insertItem('Import Creds', 561)
                                
                                       

        self.contextpopups["Host"] = popup

                    
        popup = qt.QPopupMenu(self)
        popup.insertItem('Delete Interface', 602)
        popup.insertSeparator()
        popup.insertItem('Add Service', 200)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability',400)
        popup.insertItem('List Vulnerabilities',401)
        popup.insertSeparator()
        popup.insertItem('New note', 500)
        popup.insertItem('Show notes', 501)
                                
                                       

        self.contextpopups["Interface"] = popup

                  
        popup = qt.QPopupMenu(self)
        popup.insertItem('Delete Service', 202)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability',400)
        popup.insertItem('List Vulnerabilities',401)
        popup.insertSeparator()
        popup.insertItem('New note', 500)
        popup.insertItem('Show notes', 501)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Show Credentials', 551)
        popup.insertItem('Import Creds', 561)
                                
                                       

        self.contextpopups["Service"] = popup

                       
                       
                       

                                


                     
        popup = qt.QPopupMenu(self)
        popup.insertItem('Delete Items', 202)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability Items',400)
        popup.insertSeparator()
        popup.insertItem('New note Items', 500)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Import Creds', 561)

        self.contextpopups["Service_Host"] = popup

                              
                        
        popup = qt.QPopupMenu(self)
        popup.insertItem('Add Service', 200)
        popup.insertSeparator()
        popup.insertItem('Delete Items', 202)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability Items',400)
        popup.insertSeparator()
        popup.insertItem('New note Items', 500)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Import Creds', 561)
                                
                                       

        self.contextpopups["ServiceHost_Interface"] = popup

                                    
        popup = qt.QPopupMenu(self)
                                      
                                             
        popup.insertItem('Properties', 302)
        popup.insertSeparator()
        popup.insertItem('Add Host', 800)
        popup.insertSeparator()
        popup.insertItem('Add Service', 200)
        popup.insertSeparator()
        popup.insertItem('Delete Items', 202)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability Items',400)
        popup.insertSeparator()
        popup.insertItem('New note Items', 500)
        popup.insertSeparator()
        popup.insertItem('Add Service', 200)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Import Creds', 561)
                                
                                       
        self.contextpopups["CategoryWorkspace_Interface"] = popup

                                      
        popup = qt.QPopupMenu(self)
                                      
                                             
        popup.insertItem('Properties', 302)
        popup.insertSeparator()
        popup.insertItem('Add Host', 800)
        popup.insertSeparator()
        popup.insertItem('Delete Items', 202)
        popup.insertSeparator()
        popup.insertItem('New Vulnerability Items',400)
        popup.insertSeparator()
        popup.insertItem('New note Items', 500)
        popup.insertSeparator()
        popup.insertItem('New Credential', 550)
        popup.insertItem('Import Creds', 561)
                                
                                       
        self.contextpopups["CategoryWorkspace_ServiceHost"] = popup


                                    
                              
                                                

                                                                                             
                                                             
                                                                                       
                                                                                       
    def _setupContextDispatchers(self):
        """
        Configures a context dispatcher for each kind of item shown in the tree.
        This is done because different options may be needed for each item
        """

        self.contextdispatchers[100] = self._newCategory
        self.contextdispatchers[102] = self._delCategorymenu

        self.contextdispatchers[200] = self._newService
        self.contextdispatchers[202] = self._delService

                                                           
                                                           
        self.contextdispatchers[302] = self._showWorkspaceProperties
        self.contextdispatchers[303] = self._resolveConflicts

        self.contextdispatchers[400] = self._newVuln
        self.contextdispatchers[401] = self._listVulns
        self.contextdispatchers[402] = self._listVulnsCvs
        self.contextdispatchers[403] = self._importVulnsCvs

        self.contextdispatchers[500] = self._newNote
        self.contextdispatchers[501] = self._listNotes

        self.contextdispatchers[550] = self._newCred
        self.contextdispatchers[551] = self._listCreds
        self.contextdispatchers[561] = self._importCreds

        self.contextdispatchers[600] = self._newInterface
        self.contextdispatchers[602] = self._delInterface

        self.contextdispatchers[800] = self._newHost
        self.contextdispatchers[802] = self._delHost


    def renameRootItem(self, new_name):
        self.rootitem.setText(0, new_name)
