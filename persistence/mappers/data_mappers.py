'''
Faraday Penetration Test IDE - Community Version
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

    def serialize(self, mobj):
        return {
            "type": mobj.__class__.__name__,
            "_id": mobj.getID(),
            "name": mobj.getName(),
            "owned": mobj.isOwned(),
            "parent": mobj.getParent().getID() if mobj.getParent() is not None else None,
            "owner": mobj.getOwner(),
            "description": mobj.getDescription(),
            "metadata": mobj.getMetadata().__dict__
        }

    def unserialize(self, mobj, doc):
        mobj.setName(doc.get("name"))
        mobj.setOwned(doc.get("owned"))
        mobj.setParent(self.mapper_manager.find(doc.get("parent")))
        mobj.setOwner(doc.get("owner"))
        mobj.setDescription(doc.get("description"))
        mobj.setMetadata(Metadata(doc.get("metadata")))
        self.setNotes(mobj)
        self.setVulns(mobj)
        self.setCreds(mobj)
        return mobj

    def setNotes(self, mobj):
        notes = self.mapper_manager.getMapper(
            ModelObjectNote.__name__).findForParent(mobj.getID())
        notes_dict = {k: v for (k, v) in [(note.getID(), note) for note in notes]}
        mobj.setNotes(notes_dict)

    def delete(self, mobj_id):
        mobj = self.mapper_manager.find(mobj_id)
        for child in mobj.getChilds().values():
            self.mapper_manager.remove(child.getID())
        super(ModelObjectMapper, self).delete(mobj_id)

    def setVulns(self, mobj):
        vulns = self.mapper_manager.getMapper(
            ModelObjectVuln.__name__).findForParent(mobj.getID())
        vulns_dict = {k: v for (k, v) in [(vuln.getID(), vuln) for vuln in vulns]}
        vulns_web = self.mapper_manager.getMapper(
            ModelObjectVulnWeb.__name__).findForParent(mobj.getID())
        vulns_web_dict = {k: v for (k, v) in [(vuln.getID(), vuln) for vuln in vulns_web]}
        vulns_dict.update(vulns_web_dict)
        mobj.setVulns(vulns_dict)

    def setCreds(self, mobj):
        creds = self.mapper_manager.getMapper(
            ModelObjectCred.__name__).findForParent(mobj.getID())
        creds_dict = {k: v for (k, v) in [(cred.getID(), cred) for cred in creds]}
        mobj.setCreds(creds_dict)

    def findForParent(self, obj_id):
        return self.findByFilter(parent=obj_id, type=self.mapped_class.__name__)


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
        super(HostMapper, self).unserialize(host, doc)
        host.setOS(doc.get("os"))
        host.setDefaultGateway(doc.get("default_gateway"))
        self.setInterfaces(host)
        return host

    def setInterfaces(self, host):
        interfaces = self.mapper_manager.getMapper(
            Interface.__name__).findForHost(host.getID())
        ifaces_dict = {k: v for (k, v) in [(iface.getID(), iface) for iface in interfaces]}
        host.setInterfaces(ifaces_dict)

    def findForWorkspace(self, wname):
        return self.findForParent(wname)


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
        super(InterfaceMapper, self).unserialize(iface, doc)
        iface.setMAC(doc.get("mac"))
        iface.setNetworkSegment(doc.get("network_segment"))
        for hostname in doc.get("hostnames"):
            iface.addHostname(hostname)
        iface.setIPv4(doc.get("ipv4"))
        iface.setIPv6(doc.get("ipv6"))
        iface.setPortsOpened(doc.get("ports").get("opened"))
        iface.setPortsClosed(doc.get("ports").get("closed"))
        iface.setPortsFiltered(doc.get("ports").get("filtered"))
        self.setServices(iface)
        return iface

    def setServices(self, iface):
        services = self.mapper_manager.getMapper(
            Service.__name__).findForInterface(iface.getID())
        services_dict = {k: v for (k, v) in [(srv.getID(), srv) for srv in services]}
        iface.setServices(services_dict)

    def findForHost(self, host_id):
        return self.findForParent(host_id)


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
        super(ServiceMapper, self).unserialize(srv, doc)
        srv.setProtocol(doc.get("protocol"))
        srv.setStatus(doc.get("status"))
        srv.setVersion(doc.get("version"))
        for port in doc.get("ports"):
            srv.addPort(int(port))
        return srv

    def findForInterface(self, iface_id):
        return self.findForParent(iface_id)


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
        super(NoteMapper, self).unserialize(note, doc)
        note.setText(doc.get("text"))
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
            "refs": vuln.getRefs()
        })
        return doc

    def unserialize(self, vuln, doc):
        super(VulnMapper, self).unserialize(vuln, doc)
        vuln.setDesc(doc.get("desc"))
        vuln.setSeverity(doc.get("severity"))
        vuln.setRefs(doc.get("refs"))
        return vuln

    def findForParent(self, obj_id):
        return self.findByFilter(parent=obj_id, type=self.mapped_class.__name__)


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
        super(VulnWebMapper, self).unserialize(vuln_web, doc)
        vuln_web.setWebsite(doc.get("website"))
        vuln_web.setPath(doc.get("path"))
        vuln_web.setRequest(doc.get("request"))
        vuln_web.setResponse(doc.get("response"))
        vuln_web.setMethod(doc.get("method"))
        vuln_web.setPname(doc.get("pname"))
        vuln_web.setParams(doc.get("params"))
        vuln_web.setQuery(doc.get("query"))
        vuln_web.setCategory(doc.get("category"))
        return vuln_web

    def findForParent(self, obj_id):
        return self.findByFilter(parent=obj_id, type=self.mapped_class.__name__)


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
        super(CredMapper, self).unserialize(cred, doc)
        cred.setUsername(doc.get("username"))
        cred.setPassword(doc.get("password"))
        return cred

    def findForParent(self, obj_id):
        return self.findByFilter(parent=obj_id, type=self.mapped_class.__name__)


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

    def findForWorkspace(self, wname):
        return self.findByFilter(parent=wname, type=self.mapped_class.__name__)


class WorkspaceMapper(AbstractMapper):
    mapped_class = Workspace
    dummy_args = []
    dummy_kwargs = {'name': 'dummy'}

    def __init__(self, mmanager, pmanager=None):
        super(WorkspaceMapper, self).__init__(mmanager, pmanager)

    def serialize(self, obj):
        return {
            "type": obj.__class__.__name__,
            "_id": obj.getID(),
            "name": obj.getName(),
            "description": obj.getDescription(),
            "customer": obj.getCustomer(),
            "sdate": obj.getStartDate(),
            "fdate": obj.getFinishDate()
        }

    def unserialize(self, workspace, doc):
        workspace.setName(doc.get("name"))
        workspace.setDescription(doc.get("description"))
        workspace.setCustomer(doc.get("customer"))
        workspace.setStartDate(doc.get("sdate"))
        workspace.setFinishDate(doc.get("fdate"))
        self.setHosts(workspace)
        return workspace

    def setHosts(self, workspace):
        hosts = self.mapper_manager.getMapper(
            Host.__name__).findForWorkspace(workspace.getID())
        hosts_dict = {k: v for (k, v) in [(host.getID(), host) for host in hosts]}
        workspace.setHosts(hosts_dict)


Mappers = {
    Host.__name__: HostMapper,
    Interface.__name__: InterfaceMapper,
    Service.__name__: ServiceMapper,
    ModelObjectNote.__name__: NoteMapper,
    ModelObjectVuln.__name__: VulnMapper,
    ModelObjectVulnWeb.__name__: VulnWebMapper,
    ModelObjectCred.__name__: CredMapper,
    CommandRunInformation.__name__: CommandRunMapper,
    Workspace.__name__: WorkspaceMapper
}
