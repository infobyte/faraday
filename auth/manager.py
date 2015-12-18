#!/usr/bin/env python
'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import auth.users

RolesAdmited = set(["local_admin"])
    


class Roles(object):
    """Roles for a user are defined here"""
    def __init__(self, *args):
        self.roles = []
        if set(args).issubset(RolesAdmited): 
            self.roles.extend(args)

    def __iter__(self):
        return iter(self.roles)

class codes:
    """
    an enumeration with different result/status codes
    """
    successfulLogin = 0
    badUserOrPassword = 1

    __descriptions = {
        successfulLogin :"Successful Logon",
        badUserOrPassword : "Bad username or password",
    }

    @staticmethod
    def getDescription(code):
        """
        Returns the description for a given code
        """
        return codes.__descriptions.get(code,"code does not exist")


class SecurityManager(object):
    """
    Handles the security and authentication in the system.
    it exposes some methods used to authenticate users and check permissions
    over different objects on the model.
    """
                                                                                 
                                                                               
                                                                           
                                                                            
                                       
                                                                              
                           

    def __init__(self):
        self.current_user = None

    def authenticateUser(self, username, password):
        """
        Authenticates a user.
        It returns 2 values:
        First value:
            if username and password are correct it returns a User object.
            It returns None if authentication fails
        Second value:
            returns a result code
            This code can be used later to get a description of the situation.
            To get the description use
        """
                                                                                 
                        
                                                                                 
                                   

                                                                        
        user = auth.users.User(username,password)
        self.current_user = user

        return codes.successfulLogin

    def getCurrentUser(self):
        return self.current_user

    def getUserRoles(self):
        return Roles("local_admin")

    def checkPermissions(self, operation):
        providers = self.getProviders(operation) 
        if any( [ prov.isAllowed(securityManager = self, 
                                    aUser = self.getCurrentUser(), 
                                    anOperation = operation)
                        for  prov in providers ] ):
            return True
        raise SecurityFailException("No permission for anything")

    def getProviders(self, operation): 
        return  [prov() for prov in SecurityProvider.__subclasses__() if prov.handlesOp(operation) ]


class SecurityProvider(object):
    def isAllowed(self, securityManager, aUser, anOperation):
        raise NotImplementedError("Should not implement abstract")

class WorkspacePermisionProvider(SecurityProvider):
    handles = ["syncActiveWorkspace"]
    def __init__(self):
        self.ops_per_roles = {'syncActiveWorkspace' : Roles('pentester', 'admin').roles }

    @staticmethod
    def handlesOp(anOperation):
        return anOperation in WorkspacePermisionProvider.handles

    def isAllowed(self, securityManager, aUser, anOperation):
        """ Checks if the user has the role needed to run the operation """
        allowd = any(map(lambda x: x in self.ops_per_roles[anOperation], securityManager.getUserRoles()))

        return allowd


class SecurityFailException(Exception):
    pass
