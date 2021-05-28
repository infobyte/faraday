"""
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

"""


def remove_null_caracters(string):
    string = string.replace('\x00', '')
    string = string.replace('\00', '')
    string = string.replace('\0', '')
    return string
