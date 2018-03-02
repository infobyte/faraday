#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-
"""
Faraday Penetration Test IDE
Copyright (C) 2016  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information
"""
from __future__ import print_function   
from persistence.server.server_io_exceptions  import ResourceDoesNotExist
from persistence.server import models
from utils.user_input import query_yes_no
import os
try:
    from selenium import webdriver
except Exception:
    print ("Missing dependencies: (selenium)")



__description__ = 'Takes a Schreenshot of the ip:ports of a given protocol'
__prettyname__ = 'Scheenshot_server'

def scheenshot(path, protocol, ip, port):
    driver = webdriver.PhantomJS()
    driver.set_window_size(1024, 768) # set the window size that you need 
    driver.set_page_load_timeout(5)
    try:
        driver.get(protocol + "://" + ip + ":" + port + "/")
        driver.get_screenshot_as_file (os.path.join( path , ip + "_" + port + ".png"))
    except Exception:
        print("Coudn't connect")
    finally:
        driver.quit

    return 0

def main(workspace='', args=None, parser=None):
    parser.add_argument( 'protocol', help="Desired protocol" , default="")
    parser.add_argument( '--path', help="Saves the Image in a given path", default="." )
    parsed_args = parser.parse_args(args)

    protocols = parsed_args.protocol.split(",")
    print (protocols)
    path = parsed_args.path
    
    for protocol in protocols:
        
        if not os.path.exists(path):
            print ("Invalid Path")
            exit()
        
        
        try:
            services = models.get_services(workspace)
        except ResourceDoesNotExist:
            print ("Invalid workspace name: ", workspace)
            return 1, None
        

        for service in services:
            service_protocol = service.protocol.lower()
            
            if service_protocol == protocol:
                port = str(service.ports[0])
                    
                interface_id = ".".join(service.id.split(".")[:2])
                interface = models.get_interface(workspace, interface_id)
                ip = interface.ipv4["address"]
                
                print (protocol + "://" + ip + ":" + port)
                scheenshot(path, protocol , ip, port )
    return 0, None