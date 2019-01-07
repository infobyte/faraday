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