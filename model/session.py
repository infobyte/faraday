'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import time
import datetime
import hashlib


class Session(object):
    """
    It will handle a Faraday session, that contains:
        - current user logged in
        - session start time
        - duration
        - workspace history (?...here?)
        - current workspace (?...here?)
    """

    def __init__(self, user):
        self.logged_user = user
        self.start_time = datetime.datetime.now()
                                                 
        self.workspace_history = []
        self.current_workspace = None
                                                          
        self.__token = hashlib.sha224("%s_%s" % (self.logged_user, self.start_time)).hexdigest()

    def get_token():
        return self.__token
