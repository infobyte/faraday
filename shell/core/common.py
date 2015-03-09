'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
This module contains common functions that can be used by the shell
"""
                               
def CTRL(c):
    """return the code of the given character when typed with the control
    button enabled
    """
    return ord(c) - ord("@")
