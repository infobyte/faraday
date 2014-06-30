'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from persistence.mappers.abstract_mapper import AbstractMapper
from model.hosts import Host, Interface, Service
from model.common import ModelObjectNote, ModelObjectVuln, ModelObjectVulnWeb, ModelObjectCred, Metadata


class ModeLObjectMapper(AbstractMapper):
    def __init__(self, pmanager=None):
        super(ModeLObjectMapper, self).__init__(pmanager)

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

    def populate(self, mobj, doc):
        mobj.setID(doc.get("_id"))
        mobj.setName(doc.get("name"))
        mobj.setOwned(doc.get("owned"))
        # WARNING: we need a fix for this! we're setting the id
        # of the parent not the actual object
        mobj.setParent(doc.get("parent"))
        mobj.setOwner(doc.get("owner"))
        mobj.setDescription(doc.get("description"))
        mobj.setMetadata(Metadata(doc.get("metadata")))
        return mobj

    def unserialize(self, doc):
        raise NotImplementedError("ModelObjectMapper should not be used directly")


class HostMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(HostMapper, self).__init__(pmanager)

    def serialize(self, host):
        doc = super(HostMapper, self).serialize(host)
        doc.update({
            "os": host.getOS(),
            "default_gateway": host.getDefaultGateway()
        })
        return doc

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == Host.__class__.__name__:
            return None
        host = Host(name="dummy")
        self.populate(host, doc)
        return host

    def populate(self, host, doc):
        super(HostMapper, self).populate(host, doc)
        host.setOS(doc.get("os"))
        host.setDefaultGateway(doc.get("default_gateway"))


class InterfaceMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(InterfaceMapper, self).__init__(pmanager)

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

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == Interface.__class__.__name__:
            return None
        iface = Interface(name="dummy")
        self.populate(iface, doc)
        return iface

    def populate(self, iface, doc):
        super(InterfaceMapper, self).populate(iface, doc)
        iface.setMAC(doc.get("mac"))
        iface.setNetworkSegment(doc.get("network_segment"))
        for hostname in doc.get("hostnames"):
            iface.addHostname(hostname)
        iface.setIPv4(doc.get("ipv4"))
        iface.setIPv6(doc.get("ipv6"))
        iface.setPortsOpened(doc.get("ports").get("opened"))
        iface.setPortsClosed(doc.get("ports").get("closed"))
        iface.setPortsFiltered(doc.get("ports").get("filtered"))
        return iface


class ServiceMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(ServiceMapper, self).__init__(pmanager)

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

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == Service.__class__.__name__:
            return None
        srv = Service(name="dummy")
        self.populate(srv, doc)
        return srv

    def populate(self, srv, doc):
        super(ServiceMapper, self).populate(srv, doc)
        srv.setProtocol(doc.get("protocol"))
        srv.setStatus(doc.get("status"))
        srv.setVersion(doc.get("version"))
        for port in doc.get("ports"):
            srv.addPort(int(port))
        return srv


class NoteMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(NoteMapper, self).__init__(pmanager)

    def serialize(self, note):
        doc = super(NoteMapper, self).serialize(note)
        doc.update({
            "text": note.getText()
        })
        return doc

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == ModelObjectNote.__class__.__name__:
            return None
        note = ModelObjectNote(name="dummy")
        self.populate(note, doc)
        return note

    def populate(self, note, doc):
        super(NoteMapper, self).populate(note, doc)
        note.setText(doc.get("text"))


class VulnMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(VulnMapper, self).__init__(pmanager)

    def serialize(self, vuln):
        doc = super(VulnMapper, self).serialize(vuln)
        doc.update({
            "desc": vuln.getDesc(),
            "severity": vuln.getSeverity(),
            "refs": vuln.getRefs()
        })
        return doc

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == ModelObjectVuln.__class__.__name__:
            return None
        vuln = ModelObjectVuln(name="dummy")
        self.populate(vuln, doc)
        return vuln

    def populate(self, vuln, doc):
        super(VulnMapper, self).populate(vuln, doc)
        vuln.setDesc(doc.get("desc"))
        vuln.setSeverityl(doc.get("severity"))
        vuln.setRefs(doc.get("refs"))


class VulnWebMapper(VulnMapper):
    def __init__(self, pmanager=None):
        super(VulnWebMapper, self).__init__(pmanager)

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

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == ModelObjectVulnWeb.__class__.__name__:
            return None
        vuln_web = ModelObjectVulnWeb(name="dummy")
        self.populate(vuln_web, doc)
        return vuln_web

    def populate(self, vuln_web, doc):
        super(VulnWebMapper, self).populate(vuln_web, doc)
        vuln_web.getWebsite(doc.get("website"))
        vuln_web.getPath(doc.get("path"))
        vuln_web.getRequest(doc.get("request"))
        vuln_web.getResponse(doc.get("response"))
        vuln_web.getMethod(doc.get("method"))
        vuln_web.getPname(doc.get("pname"))
        vuln_web.getParams(doc.get("params"))
        vuln_web.getQuery(doc.get("query"))
        vuln_web.getCategory(doc.get("category"))


class CredMapper(ModeLObjectMapper):
    def __init__(self, pmanager=None):
        super(CredMapper, self).__init__(pmanager)

    def serialize(self, cred):
        doc = super(CredMapper, self).serialize(cred)
        doc.update({
            "username": cred.getUsername(),
            "password": cred.getPassword()
        })
        return doc

    def unserialize(self, doc):
        if not doc or doc.get("type", "Undefined") == ModelObjectCred.__class__.__name__:
            return None
        cred = ModelObjectCred(name="dummy")
        self.populate(cred, doc)
        return cred

    def populate(self, cred, doc):
        super(CredMapper, self).populate(cred, doc)
        cred.setUsername(doc.get("username"))
        cred.setPassword(doc.get("password"))
