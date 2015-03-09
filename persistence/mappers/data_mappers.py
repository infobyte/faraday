'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from persistence.mappers.abstract_mapper import AbstractMapper
from model.hosts import Host, Interface, Service
from model.common import ModelObjectNote, ModelObjectVuln, ModelObjectVulnWeb, ModelObjectCred, Metadata
from model.commands_history import CommandRunInformation
from model.workspace import Workspace


#Every mapper has to be registered in the dict at the end of the file


class ModelObjectMapper(AbstractMapper):
    mapped_class = None
    dummy_args = []
    dummy_kwargs = {}

    def __init__(self, mmanager, pmanager=None):
        super(ModelObjectMapper, self).__init__(mmanager, pmanager)
        self.children = []

    def serialize(self, mobj):
        return {
            "type": mobj.class_signature,
            "_id": mobj.getID(),
            "name": mobj.getName(),
            "owned": mobj.isOwned(),
            "parent": mobj.getParent().getID() if mobj.getParent() is not None else None,
            "owner": mobj.getOwner(),
            "description": mobj.getDescription(),
            "metadata": mobj.getMetadata().__dict__
        }

    def unserialize(self, mobj, doc):
        self.children = self.findChildren(mobj.getID())
        mobj.setName(doc.get("name"))
        mobj.setOwned(doc.get("owned"))
        if doc.get("parent", None):
            mobj.setParent(self.mapper_manager.find(doc.get("parent")))
        mobj.setOwner(doc.get("owner"))
        mobj.setDescription(doc.get("description"))
        mobj.setMetadata( Metadata('').fromDict(mobj.getMetadata().__dict__))
        if self.children:
            self.setNotes(mobj)
            self.setVulns(mobj)
            self.setCreds(mobj)
        return mobj

    def delete(self, mobj_id):
        mobj = self.mapper_manager.find(mobj_id)
        for child in mobj.getChilds().values():
            self.mapper_manager.remove(child.getID())
        super(ModelObjectMapper, self).delete(mobj_id)

    def _loadChilds(self, type):
        ids = [doc['_id']
               for doc in self.children
               if doc.get("type") == type]
        mapper = self.mapper_manager.getMapper(type)
        obj_dict = {}
        for id in ids:
            obj = mapper.load(id)
            obj_dict[obj.getID()] = obj
        return obj_dict

    def setNotes(self, mobj):
        mobj.setNotes(
            self._loadChilds(ModelObjectNote.class_signature))

    def setVulns(self, mobj):
        vulns = self._loadChilds(ModelObjectVuln.class_signature)
        vulns_web = self._loadChilds(ModelObjectVulnWeb.class_signature)
        vulns.update(vulns_web)
        mobj.setVulns(vulns)

    def setCreds(self, mobj):
        mobj.setCreds(
            self._loadChilds(ModelObjectCred.class_signature))

    def findForParent(self, obj_id):
        return self.findByFilter(parent=obj_id, type=self.mapped_class.class_signature)

    def findChildren(self, obj_id):
        return self.getChildren(obj_id)
        #return self.findByFilter(parent=obj_id, type=None)


class HostMapper(ModelObjectMapper):
    mapped_class = Host
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(HostMapper, self).__init__(mmanager, pmanager)

    def serialize(self, host):
        doc = super(HostMapper, self).serialize(host)
        doc.update({
            "os": host.getOS(),
            "default_gateway": host.getDefaultGateway()
        })
        return doc

    def unserialize(self, host, doc):
        host.setOS(doc.get("os"))
        host.setDefaultGateway(doc.get("default_gateway"))
        super(HostMapper, self).unserialize(host, doc)
        self.setInterfaces(host)
        return host

    def setInterfaces(self, host):
        host.setInterfaces(
            self._loadChilds(Interface.class_signature))


class InterfaceMapper(ModelObjectMapper):
    mapped_class = Interface
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(InterfaceMapper, self).__init__(mmanager, pmanager)

    def serialize(self, iface):
        doc = super(InterfaceMapper, self).serialize(iface)
        doc.update({
            "mac": iface.getMAC(),
            "network_segment": iface.getNetworkSegment(),
            "hostnames": [hname for hname in iface.getHostnames()],
            "ipv4": iface.getIPv4(),
            "ipv6": iface.getIPv6(),
            "ports": {
                "opened": iface.getPortsOpened(),
                "closed": iface.getPortsClosed(),
                "filtered": iface.getPortsFiltered(),
            }
        })
        return doc

    def unserialize(self, iface, doc):
        iface.setMAC(doc.get("mac"))
        iface.setNetworkSegment(doc.get("network_segment"))
        for hostname in doc.get("hostnames"):
            iface.addHostname(hostname)
        iface.setIPv4(doc.get("ipv4"))
        iface.setIPv6(doc.get("ipv6"))
        iface.setPortsOpened(doc.get("ports").get("opened"))
        iface.setPortsClosed(doc.get("ports").get("closed"))
        iface.setPortsFiltered(doc.get("ports").get("filtered"))
        super(InterfaceMapper, self).unserialize(iface, doc)
        self.setServices(iface)
        return iface

    def setServices(self, iface):
        iface.setServices(
            self._loadChilds(Service.class_signature))


class ServiceMapper(ModelObjectMapper):
    mapped_class = Service
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(ServiceMapper, self).__init__(mmanager, pmanager)

    def serialize(self, srv):
        doc = super(ServiceMapper, self).serialize(srv)
        doc.update({
            "protocol": srv.getProtocol(),
            "status": srv.getStatus(),
            "version": srv.getVersion(),
            "ports": [port for port in srv.getPorts()],
            #"interfaces": [id for id in srv._getAllIDs("_interfaces")]
        })
        return doc

    def unserialize(self, srv, doc):
        srv.setProtocol(doc.get("protocol"))
        srv.setStatus(doc.get("status"))
        srv.setVersion(doc.get("version"))
        for port in doc.get("ports"):
            srv.addPort(int(port))
        super(ServiceMapper, self).unserialize(srv, doc)
        return srv


class NoteMapper(ModelObjectMapper):
    mapped_class = ModelObjectNote
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(NoteMapper, self).__init__(mmanager, pmanager)

    def serialize(self, note):
        doc = super(NoteMapper, self).serialize(note)
        doc.update({
            "text": note.getText()
        })
        return doc

    def unserialize(self, note, doc):
        note.setText(doc.get("text"))
        super(NoteMapper, self).unserialize(note, doc)
        return note


class VulnMapper(ModelObjectMapper):
    mapped_class = ModelObjectVuln
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(VulnMapper, self).__init__(mmanager, pmanager)

    def serialize(self, vuln):
        doc = super(VulnMapper, self).serialize(vuln)
        doc.update({
            "desc": vuln.getDesc(),
            "severity": vuln.getSeverity(),
            "resolution": vuln.getResolution(),
            "refs": vuln.getRefs(),
            "data": vuln.getData()
        })
        return doc

    def unserialize(self, vuln, doc):
        vuln.setDesc(doc.get("desc"))
        vuln.setSeverity(doc.get("severity"))
        vuln.setResolution(doc.get("resolution"))
        vuln.setRefs(doc.get("refs"))
        vuln.setData(doc.get("data", ""))
        super(VulnMapper, self).unserialize(vuln, doc)
        return vuln


class VulnWebMapper(VulnMapper):
    mapped_class = ModelObjectVulnWeb
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(VulnWebMapper, self).__init__(mmanager, pmanager)

    def serialize(self, vuln_web):
        doc = super(VulnWebMapper, self).serialize(vuln_web)
        doc.update({
            "website": vuln_web.getWebsite(),
            "path": vuln_web.getPath(),
            "request": vuln_web.getRequest(),
            "response": vuln_web.getResponse(),
            "method": vuln_web.getMethod(),
            "pname": vuln_web.getPname(),
            "params": vuln_web.getParams(),
            "query": vuln_web.getQuery(),
            "category": vuln_web.getCategory()
        })
        return doc

    def unserialize(self, vuln_web, doc):
        vuln_web.setWebsite(doc.get("website"))
        vuln_web.setPath(doc.get("path"))
        vuln_web.setRequest(doc.get("request"))
        vuln_web.setResponse(doc.get("response"))
        vuln_web.setMethod(doc.get("method"))
        vuln_web.setPname(doc.get("pname"))
        vuln_web.setParams(doc.get("params"))
        vuln_web.setQuery(doc.get("query"))
        vuln_web.setCategory(doc.get("category"))
        super(VulnWebMapper, self).unserialize(vuln_web, doc)
        return vuln_web


class CredMapper(ModelObjectMapper):
    mapped_class = ModelObjectCred
    dummy_args = []
    dummy_kwargs = {}

    def __init__(self, mmanager, pmanager=None):
        super(CredMapper, self).__init__(mmanager, pmanager)

    def serialize(self, cred):
        doc = super(CredMapper, self).serialize(cred)
        doc.update({
            "username": cred.getUsername(),
            "password": cred.getPassword()
        })
        return doc

    def unserialize(self, cred, doc):
        cred.setUsername(doc.get("username"))
        cred.setPassword(doc.get("password"))
        super(CredMapper, self).unserialize(cred, doc)
        return cred


class CommandRunMapper(AbstractMapper):
    mapped_class = CommandRunInformation
    dummy_args = []
    dummy_kwargs = {}

    def __init__(self, mmanager, pmanager=None):
        super(CommandRunMapper, self).__init__(mmanager, pmanager)

    def serialize(self, obj):
        return obj.__dict__

    def unserialize(self, cmd, doc):
        for k, v in doc.items():
            setattr(cmd, k, v)
        return cmd


class WorkspaceMapper(AbstractMapper):
    mapped_class = Workspace
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(WorkspaceMapper, self).__init__(mmanager, pmanager)

    def serialize(self, obj):
        return {
            "type": obj.class_signature,
            "_id": obj.getID(),
            "name": obj.getName(),
            "description": obj.getDescription(),
            "customer": obj.getCustomer(),
            "sdate": obj.getStartDate(),
            "fdate": obj.getFinishDate()
        }

    def findChildren(self, obj_id):
        return self.findByFilter(parent=obj_id, type=None)

    def unserialize(self, workspace, doc):
        children = self.findChildren(
            workspace.getID()) + self.findChildren(None) + self.findChildren("None")
        workspace.setName(doc.get("name", doc.get("_id")))
        workspace.setDescription(doc.get("description"))
        workspace.setCustomer(doc.get("customer"))
        workspace.setStartDate(doc.get("sdate"))
        workspace.setFinishDate(doc.get("fdate"))
        self.setHosts(workspace, children)
        return workspace

    def setHosts(self, workspace, docs):
        ids = [doc['_id']
               for doc in docs
               if doc.get("type") == Host.class_signature]
        mapper = self.mapper_manager.getMapper(Host.class_signature)
        host_dict = {}
        for id in ids:
            host = mapper.load(id)
            host_dict[host.getID()] = host

        workspace.setHosts(host_dict)


Mappers = {
    Host.class_signature: HostMapper,
    Interface.class_signature: InterfaceMapper,
    Service.class_signature: ServiceMapper,
    ModelObjectNote.class_signature: NoteMapper,
    ModelObjectVuln.class_signature: VulnMapper,
    ModelObjectVulnWeb.class_signature: VulnWebMapper,
    ModelObjectCred.class_signature: CredMapper,
    CommandRunInformation.class_signature: CommandRunMapper,
    Workspace.class_signature: WorkspaceMapper
}
