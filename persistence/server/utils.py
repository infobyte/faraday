#!/usr/bin/python2.7
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

class MoreThanOneObjectFoundByID(Exception):
    def __init__(self, faulty_list):
        self.faulty_list = faulty_list

    def __str__(self):
        return ("More than one object has been found."
                "These are all the objects found with the same ID: {0}"
                .format(self.faulty_list))

class WrongObjectSignature(Exception):
    def __init__(self, param):
        self.param = param

    def __str__(self):
        return ("object_signature must be either 'host', 'vuln', 'vuln_web',"
                "'interface' 'service', 'credential' or 'note' and it was {0}"
                .format(self.param))

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

def get_object_properties(obj):
    return {'id': obj.getID(),
            'name': obj.getName(),
            'description': obj.getDescription(),
            'metadata': obj.getMetadata(),
            'owned': obj.isOwned(),
            'owner': obj.getOwner()
            }

def get_host_properties(host):
    host_dict = {'os': host.getOS(),
                 'default_gateway': host.getDefaultGateway()}
    host_dict.update(get_object_properties(host))
    return host_dict

def get_interface_properties(interface):
    interface_dict = {'mac': interface.getMAC(),
                      'hostnames': interface.getHostnames(),
                      'network_segment': interface.getNetworkSegment(),
                      'ipv4':  interface.getIPv4(),
                      'ipv6': interface.getIPv6()
                      }
    interface_dict.update(get_object_properties(interface))
    return interface_dict

def get_service_properties(service):
    service_dict = {'ports': service.getPorts(),
                    'protocol': service.getProtocol(),
                    'status': service.getStatus(),
                    'version': service.getVersion()
                    }
    service_dict.update(get_object_properties(service))
    return service_dict

def get_vuln_properties(vuln):
    vuln_dict = {'confirmed': vuln.getConfirmed(),
                 'data': vuln.getData(),
                 'refs': vuln.getRefs(),
                 'severity': vuln.getSeverity(),
                 'resolution': vuln.getResolution(),
                 'desc': vuln.getDesc()}
    vuln_dict.update(get_object_properties(vuln))
    return vuln_dict

def get_vuln_web_properties(vuln_web):
    vuln_web_dict = {'method': vuln_web.getMethod(),
                     'params': vuln_web.getParams(),
                     'request': vuln_web.getRequest(),
                     'response': vuln_web.getResponse(),
                     'website': vuln_web.getWebsite(),
                     'path': vuln_web.getPath(),
                     'pname': vuln_web.getPname(),
                     'query': vuln_web.getQuery(),
                     }
    vuln_web_dict.update(get_object_properties(vuln_web))
    vuln_web_dict.update(get_vuln_properties(vuln_web))
    return vuln_web_dict

def get_note_properties(note):
    note_dict = {'text': note.getText()}
    note_dict.update(get_object_properties(note))
    return note_dict

def get_credential_properties(credential):
    cred_dict = {'username': credential.getUsername(),
                 'password': credential.getPassword()}
    cred_dict.update(get_object_properties(credential))
    return cred_dict

def get_command_properties(command):
    return {'id': command.getID(),
            'command': command.command,
            'user': command.user,
            'ip': command.ip,
            'hostname': command.hostname,
            'itime': command.itime,
            'duration': command.duration,
            'params': command.params}
