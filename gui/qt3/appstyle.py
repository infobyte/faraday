#!/usr/bin/env python
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

"""
Custom GUI Styles for the application
"""
             
                                                
                                                
                                          
                                                     

import qt

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

class CustomWindowsStyle(qt.QWindowsStyle):
    def __init__(self):
        qt.QWindowsStyle.__init__(self)

                                    
                        
                                    

class CustomCommonStyle(qt.QCommonStyle):
    def __init__(self):
        qt.QCommonStyle.__init__(self)
