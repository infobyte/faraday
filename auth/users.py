#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import os
import sys
import uuid

                                                                                

class User(object):
    """
    This represents a user on the system.
    Users are assigned to work on different workspaces and
    some permissions are configured.
    A user can be part of groups.
    """
    def __init__(self, name, passwd = "", display_name = "", groups = [], level = 0):
                                                                                 
        self.name       = name
        self.__id       = uuid.uuid4()                       
                                                                        
        self.display_name = display_name or name
        self._groups    = []
        self._level     = level
                                                                          
                                                      
        self.__password = passwd
                                
                                     

        self.lastlogon = None

                                                                                
