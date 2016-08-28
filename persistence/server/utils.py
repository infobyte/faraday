class MoreThanOneObjectFoundByID(Exception):
    def __init__(self, faulty_list):
        self.faulty_list = faulty_list

    def __str__(self):
        return ("More than one object has been found."
                "These are all the objects found with the same ID: {0}"
                .format(self.faulty_list))

def force_unique(lst):
    """Takes a list and return its only member if the list len is 1,
    None if list is empty or raises an MoreThanOneObjectFoundByID error
    if list has more than one element.
    """
    if len(lst) == 1:
        return lst[0]
    elif len(lst) == 0:
        return None
    else:
        raise MoreThanOneObjectFoundByID(lst)

def get_host_properties(host):
    return {'id': host.getID(),
            'name': host.getName(),
            'description': host.getDescription(),
            'os': host.getOS(),
            'default_gateway': host.getDefaultGateway(),
            'metadata': host.getMetadata(),
            'owned': host.isOwned(),
            'owner': host.getOwner()}

def get_interface_properties(interface):
    return {'id': interface.getID(),
            'name': interface.getName(),
            'description': interface.getDescription(),
            'mac': interface.getMAC(),
            'owned': interface.isOwned(),
            'hostnames': interface.getHostnames(),
            'network_segment': interface.getNetworkSegment(),
            'ipv4_address':  interface.getIPv4Address(),
            'ipv4_gateway': interface.getIPv4Gateway(),
            'ipv4_dns': interface.getIPv4DNS(),
            'ipv4_mask': interface.getIpv4Mask(),
            'ipv6_address':  interface.getIPv6Address(),
            'ipv6_gateway': interface.getIPv6Gateway(),
            'ipv6_dns': interface.getIPv6DNS(),
            'ipv6_mask': interface.getIPv6Prefix(),
            'metadata': interface.getMetadata()}

def get_service_properties(service):
    return {'id': service.getID(),
            'name': service.getName(),
            'description': service.getDescription(),
            'ports': service.getPorts(),
            'owned': service.isOwned(),
            'protocol': service.getProtocol(),
            'status': service.getStatus(),
            'version': service.getVersion(),
            'metadata': service.getMetatada()}

def get_vuln_properties(vuln):
    return {'id': vuln.getID(),
            'name': vuln.getName(),
            'description': vuln.getDescription(),
            'confirmed': vuln.getConfirmed(),
            'data': vuln.getData(),
            'refs': vuln.getRefs(),
            'severity': vuln.getSeverity(),
            'metadata': vuln.getMetadata()}

def get_vuln_web_properties(vuln_web):
    return {'id': vuln_web.getID(),
            'name': vuln_web.getName(),
            'description': vuln_web.getDescription(),
            'confirmed': vuln_web.getConfirmed(),
            'data': vuln_web.getData(),
            'refs': vuln_web.getRefs(),
            'severity': vuln_web.getSeverity(),
            'resolution': vuln_web.getResolution(),
            'attachments': vuln_web.getAttachments(),
            'easeofresolution': vuln_web.getEaseOfResolution(),
            'hostnames': vuln_web.getHostnames(),
            'impact': vuln_web.getImpact(),
            'method': vuln_web.getMethod(),
            'owned': vuln_web.isOwned(),
            'owner': vuln_web.getOwner(),
            'params': vuln_web.getParams(),
            'parent': vuln_web.getParent(),
            'request': vuln_web.getRequest(),
            'response': vuln_web.getResponse(),
            'service': vuln_web.getService(),
            'status': vuln_web.getStatus(),
            'tags': vuln_web.getTags(),
            'target': vuln_web.getTarget(),
            'website': vuln_web.getWebsite(),
            'metadata': vuln_web.getMetadata()}

def get_note_properties(note):
    return {'id': note.getID(),
            'name': note.getName(),
            'description': note.getDescription(),
            'text': note.getText()}

def get_credential_properties(credential):
    return {'id': credential.getID(),
            'username': credential.getUsername(),
            'password': credential.getPassword()}

def get_command_properties(command):
    return {'id': command.getID(),
            'command': command.command,
            'user': command.user,
            'ip': command.ip,
            'hostname': command.hostname,
            'itime': command.itime,
            'duration': command.duration,
            'params': command.params}
