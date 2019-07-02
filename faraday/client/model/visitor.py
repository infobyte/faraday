'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
Contains base classes used to represent the application model
and some other common objects and functions used in the model
"""


class ModelObjectVisitor(object):
    def visit(self, modelObjectInstance):
        raise NotImplemented('Abstract method')


class VulnsLookupVisitor(ModelObjectVisitor):
    def __init__(self, vulnId):
        self.vulnId = vulnId
        self.parents = []
        self.vulns = []

    def visit(self, modelObject):
        vuln = modelObject.getVuln(self.vulnId)
        parents = []
        if vuln:
            self.vulns.append(vuln)
            parent = vuln.getParent()
            while parent:
                parents.append(parent)
                parent = parent.getParent()

        self.parents.append(parents) 
