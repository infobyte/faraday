#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2015  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

"""
Create a report using the libs.reports package.
Send the information to Faraday, using RPC API.

"""

import xmlrpclib
import pprint
import sys
import os

if '.' not in sys.path: sys.path.append('.')
if 'libs' not in sys.path: sys.path.append('libs')
if 'exploits' not in sys.path: sys.path.append('./exploits/server/clientd')

from exploitutils import *

from libs.reports import utils
from libs.reports import canvas_report
import report as ClientdReport

from ExploitTypes.utility import Utility

NAME                           = 'faraday_report'
VERSION                        = '0.1'
DESCRIPTION                    = 'Creates a report from CANVAS event pickles and send the information to Faraday.'

DOCUMENTATION                  = {}
DOCUMENTATION['Repeatability'] = 'Infinite'
DOCUMENTATION['Usage']         = """Select the type of report to generate and supply
the path to a data pickle, in addition to the URL faraday RPC"""

DOCUMENTATION['Notes']         = NOTES = """This module is not backwards compatible
with reporting pickles created by previous versions of CANVAS.

It should also be noted that the new reporting pickle is not compatible with
with any of the previous CANVAS reporting modules, such as "report_timeline".
"""

PROPERTY                       = {}
PROPERTY['TYPE']               = 'Reporting'
PROPERTY['SITE']               = 'Local'

DEFAULT_DATA_FILE              = 'report.pkl'
DEFAULT_FARADAY_RPC            = 'http://127.0.0.1:9876/'
DEFAULT_DATA_PATH              = utils.get_reports_path(filename=DEFAULT_DATA_FILE)



class Host():
    def __init__(self, ip, host_id):

        self.ip = ip
        self.host_id = host_id
        #{IP:INTERFACE_ID}
        self.dict_interfaces = {}
        #{IP:{PORT:SERVICE_ID}}
        self.dict_services = {}

    def addInterface(self, ip_interface, interface_id):

        self.dict_interfaces.update({ip_interface: interface_id})

    def getInterfaceId(self, ip_interface):

        try:
            return self.dict_interfaces[ip_interface]
        except:
            return None

    def addService(self, ip_interface, port, service_id):

        if ip_interface in self.dict_services:
            temp = self.dict_services[ip_interface]
            temp.update({port: service_id})
            self.dict_services.update({ip_interface: temp})
        else:
            self.dict_services.update({ ip_interface: {port:service_id} })

    def getServiceId(self, ip_interface, port):

        try:
            return self.dict_services[ip_interface][port]
        except:
            return None



class ParsingCanvas():

    def __init__(self, faraday_api, data_file):

        self.faraday_api = faraday_api
        self.data_file = data_file
        self.data = canvas_report.Collector().collect(self.data_file)
        self.host_list = []

    def getAndCreateNewHost(self, node):

        #Get OS
        try:
            for attack in node['attacks']:
                if attack['node_type'] != '':
                    op_sy = attack['node_type']
                break
        except:
            op_sy = 'Undefined'

        #Create Host
        host_id = self.faraday_api.createAndAddHost(
        node['resolved_from'],
        op_sy,
        'Unknown',
        'Unknown',
        node['ip']
        )
        host = Host(node['ip'], host_id)
        self.host_list.append(host)
        return host

    def getSeverity(self, cvss):

        #Get severity CVSS version 3
        values_cvss = {3.9:'Low', 6.9:'Medium', 8.9:'High', 10.0:'Critical' }
        values =  [3.9, 6.9, 8.9, 10.0]
        #Get the score more close...
        score = min(values, key=lambda x:abs(x-cvss))
        return values_cvss[score]

    def getAndCreateVulnerabilities(self, node, host):

        #Get interface id
        for host in self.host_list:
            interface_id = host.getInterfaceId(node['ip'])
            if interface_id != None:
                break

        for attack in node['attacks']:

            #Create service
            for x, y, name_exploit in self.data['_exploits']:

                if name_exploit == attack['name']:

                    port = self.data['_exploits'][(x, y, name_exploit)]['arguments']['port']
                    ip = self.data['_exploits'][(x, y, name_exploit)]['arguments']['host']

                    #Check service created
                    service_id = host.getServiceId(ip, port)
                    if service_id != None:
                        break

                    service_id = self.faraday_api.createAndAddServiceToInterface(
                    host.host_id,
                    interface_id,
                    str(int(float(port))),
                    'tcp?',
                    int(float(port))
                    )

                    host.addService(ip, port, service_id)
                    break

            #Create vulnerability
            try:
                title = attack['title']
                description = self.data['exploits'][attack['name']]['description']
                cve = self.data['exploits'][attack['name']]['cve']
                severity = self.data['exploits'][attack['name']]['properties']['CVSS']
                severity = self.getSeverity(float(severity))
            except:
                title = ''
                description = ''
                cve = []
                severity = ''

            self.faraday_api.createAndAddVulnToService(
            host.host_id,
            service_id,
            title,
            description,
            [cve],
            severity,
            ''
            )


    def getAndCreateInterfaces(self, node, host):
        #Get Interfaces Ipv6 or Ipv4
        for element in self.data['_nodes']:

            if element['ip'] == node['ip']:

                for ip in element['ips']:
                    #Ipv6
                    if ip.find(':') > -1 and ip != '127.0.0.1':

                        interface_id = self.faraday_api.createAndAddInterface(
                        host.host_id,
                        ip,
                        '00:00:00:00:00:00',
                        '0.0.0.0',
                        '0.0.0.0',
                        '0.0.0.0',
                        [],
                        ip
                        )
                        host.addInterface(ip, interface_id)
                    #Ipv4
                    elif ip.find(':') <= -1 and ip != '127.0.0.1':

                        interface_id = self.faraday_api.createAndAddInterface(
                        host.host_id,
                        ip,
                        '00:00:00:00:00:00',
                        ip
                        )
                        host.addInterface(ip, interface_id)
            break

    def getAndCreateStatisticsLog(self, data_file, data_nodes):

        #Canvas Statistics
        ip_callback = data_nodes[0]['parent']['ip']
        host_id = self.faraday_api.createAndAddHost(ip_callback)

        text = (
        'Exploits attempted: {0}\n'
        'Exploits successful : {1}\n'
        'Hosts attacked: {2}\n'
        'Hosts compromised: {3}\n'
        'Hosts discovered: {4}\n'
        'Total exploits attempted: {5}\n'
        'Total exploits successful: {6}\n'
        ).format(
        self.data['stats']['exploits_attempted'],
        self.data['stats']['exploits_successful'],
        self.data['stats']['hosts_attacked'],
        self.data['stats']['hosts_compromised'],
        self.data['stats']['hosts_discovered'],
        self.data['stats']['total_exploits_attempted'],
        self.data['stats']['total_exploits_successful']
        )

        self.faraday_api.createAndAddNoteToHost(host_id, 'Statistics canvas', text)

        #Canvas log
        log_path = os.path.dirname(data_file)
        with open( os.path.join( log_path, 'CANVAS.log'), 'r') as file_log:

            data_to_save = []
            for line in file_log.readlines():

                if line.find('canvasexploit.py') > -1 or line.find('.py] -') == -1 :
                    data_to_save.append(line.strip('\r\n'))

            data_save = pprint.pformat(data_to_save)
            self.faraday_api.createAndAddNoteToHost(host_id, 'Canvas Log', data_save )

    def parsingAndSendCanvas(self):

        #Iterate over hosts and create the entities.
        hosts = self.data['hosts']

        for ip in hosts:

            for obj_host in self.host_list:

                #Ip is a interface , not is a new host.
                if obj_host.getInterfaceId(ip) != None:
                    self.getAndCreateVulnerabilities(
                    hosts[ip],
                    obj_host
                    )
                break

            host = self.getAndCreateNewHost(hosts[ip])
            self.getAndCreateInterfaces(hosts[ip], host)
            self.getAndCreateVulnerabilities(hosts[ip], host)

        self.getAndCreateStatisticsLog(self.data_file, self.data['_nodes'])



class ParsingClientd(ParsingCanvas):

    def __init__(self, faraday_api, data_file):

        self.faraday_api = faraday_api
        self.data_file = data_file
        self.data = ClientdReport.Collector().collect(data_file)

    def parsingAndSendClientd(self):
        #Iterate over sessions and create the entities.
        hosts = self.data['sessions']

        for session in hosts:

            #Get data
            ip = hosts[session]['ip']
            agent = hosts[session]['agent']
            os = self.data['clients'][ip]['agents'][agent]['os']
            info_host = self.data['clients'][ip]['agents'][agent]

            #Create Host
            host_id = self.faraday_api.createAndAddHost(
            ip,
            os,
            'Unknown',
            'Unknown',
            'Unknown'
            )

            #'IE Flash' is a keyword only for Internet Explorer??'
            try:
                flash_player = info_host['plugins']['IE Flash']
            except:
                flash_player = "Unknown"

            #Get information about host
            text = (
            'Platform: {0}\n'
            'Language: {1}\n'
            'Browser: {2}\n'
            'Plugins: Flash: {3}\n'
                     'Java : {4}\n'
                     'Office: {5}\n'
            'Agent: {6}\n'
            'Email: {7}\n'
            'Country: {8}\n'
            'Cpu: {9}\n'
            'Os:  {10}\n'
            ).format(
            info_host['platform'],
            info_host['language'],
            info_host['browser'],
            flash_player,
            info_host['plugins']['Java'],
            info_host['plugins']['Office'],
            agent,
            self.data['clients'][ip]['email'],
            self.data['clients'][ip]['ip_country'],
            info_host['cpu'],
            os
            )

            #Create note with recon data.
            self.faraday_api.createAndAddNoteToHost(host_id, 'Recon Information', text)

            #If any exploit is successful
            if (self.data['clients'][ip]['session_count'] >= 1):

                for name, session_id in self.data['attacks']:

                    #If session Ids equals and exploits is sucessful
                    if session_id == hosts[session]['sid']:
                        if self.data['attacks'][(name, session_id)]['successful'] == True:

                            #Get info about vulnerability
                            name = self.data['attacks'][(name, session_id)]['exploit']['name']
                            description= self.data['attacks'][(name, session_id)]['exploit']['description']
                            ref = [self.data['attacks'][(name, session_id)]['exploit']['cve']]

                            #Create vulnerability
                            self.faraday_api.createAndAddVulnToHost(
                            host_id,
                            name,
                            description,
                            ref,
                            '',
                            ''
                            )



class theexploit(Utility):

    def __init__(self):

        Utility.__init__(self)
        self.name = NAME
        self.report_type = 'canvas'
        self.data_file = DEFAULT_DATA_PATH
        self.faraday_rpc = DEFAULT_FARADAY_RPC

    def getargs(self):

        self.getarg('report_type')
        self.getarg('data_file')
        self.getarg('faraday_rpc')

    def run(self):

        self.getargs()

        msg = 'Sending information to Faraday ...'
        self.log(msg)
        self.setInfo(msg)

        try:
            faraday_api = xmlrpclib.ServerProxy(self.faraday_rpc)
        except Exception as e:

            self.log('Faraday RPC API Exception: {0}'.format(e.message))
            self.setInfo('Faraday RPC API Exception: {0}'.format(e.message))

        if self.report_type == 'canvas':
            parser = ParsingCanvas(faraday_api, self.data_file)
            parser.parsingAndSendCanvas()
        else:
            parser = ParsingClientd(faraday_api, self.data_file)
            parser.parsingAndSendClientd()

        #Finished.
        msg = 'Done. Information sent to faraday.'
        self.log(msg)
        self.setInfo(msg)
        return 1

def select_path(b, gtk, dialog, action, widget):

    dialog = gtk.FileChooserDialog('Select filename...', dialog, action,
        (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OPEN, gtk.RESPONSE_OK))
    try:
        dialog.set_filename(widget.get_text())

        if dialog.run() == gtk.RESPONSE_OK:
            fname = dialog.get_filename()
            widget.set_text(fname)
    finally:
        dialog.destroy()

def dialog_update(gtk, wtree):

    dialog = wtree.get_widget('exploit_dialog')
    signal_ids = []

    widget = wtree.get_widget('report_type')
    widget.set_active(0)

    widget = wtree.get_widget('data_file')
    widget.set_text(DEFAULT_DATA_PATH)

    button = wtree.get_widget('pickle_file_button')
    sig = button.connect('clicked', select_path, gtk, dialog,
        gtk.FILE_CHOOSER_ACTION_OPEN, widget)
    signal_ids.append((button, sig))

    widget = wtree.get_widget('faraday_rpc')
    widget.set_text(DEFAULT_FARADAY_RPC)

    def disconnect(w):

        for w, sig in signal_ids:
            w.disconnect(sig)
    sig = dialog.connect('hide', disconnect)
    signal_ids.append((dialog, sig))

if __name__ == '__main__':

    app = theexploit()
    ret = standard_callback_commandline(app)
