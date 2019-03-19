'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os

from faraday import FARADAY_BASE

def filter_services():
    open_file = open(os.path.join(FARADAY_BASE,'plugins/port_mapper.txt'),"r")
    mapper = open_file.read()
    filtering = mapper.split('\n')
    services = []

    for item in filtering:
        tup = ()
        filt = filter(len,item.split('\t'))
        tup = (filt[0],filt[1])
        services.append(tup)

    return services

def get_all_protocols():
    protocols = [
        'ip',
        'tcp',
        'udp',
        'icmp',
        'sctp',
        'hopopt',
        'igmp',
        'ggp',
        'ip-encap',
        'st',
        'egp',
        'igp',
        'pup',
        'hmp',
        'xns-idp',
        'rdp',
        'iso-tp4',
        'dccp',
        'xtp',
        'ddp',
        'idpr-cmtp',
        'ipv6',
        'ipv6-route',
        'ipv6-frag',
        'idrp',
        'rsvp',
        'gre',
        'ipsec-esp',
        'ipsec-ah',
        'skip',
        'ipv6-icmp',
        'ipv6-nonxt',
        'ipv6-opts',
        'rspf cphb',
        'vmtp',
        'eigrp',
        'ospfigp',
        'ax.25',
        'ipip',
        'etherip',
        'encap',
        'pim',
        'ipcomp',
        'vrrp',
        'l2tp',
        'isis',
        'fc',
        'udplite',
        'mpls-in-ip',
        'hip',
        'shim6',
        'wesp',
        'rohc',
        'mobility-header'
    ]

    for item in protocols:
        yield item
