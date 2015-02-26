'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
class ModelObjectDiff(object):
    def __init__(self, objLeft, objRight):
        if not isinstance(objLeft, objRight.__class__):
            raise Exception("Cannot compare objects of different classes. objLeft (%s) vs objRight (%s)"
                            % (objLeft.__class__.__name__, objRight.__class__.__name__))
        self.obj1, self.obj2 = objLeft, objRight

        self.conflicting = []
        self.conflicting.extend(self.getPropertiesDiff()) 
        
        self.only_in_obj1 = {}
        self.only_in_obj2 = {}

    def existDiff(self):
        return bool(self.conflicting) or bool(self.only_in_obj1) or bool(self.only_in_obj2)


    def getPropertiesDiff(self): 
        prop_diff = {}
        for attrdesc, attrname in self.obj1.publicattrsrefs.items():
            info = lambda attr_ref: attr_ref() if callable(attr_ref) else attr_ref
            prop1 = info(self.obj1.__getattribute__(attrname))  
            prop2 = info(self.obj2.__getattribute__(attrname))
            if prop1 != prop2:
                prop_diff[attrdesc] = (prop1, prop2)

        return prop_diff

    def getDifferences(self, ObjDiff, getAllFunc, getById):
        """ Polymorphic method to get the differences between the list of objects on a ModelObject.
        Pass the ObjectDiff class, the unbound method to get all the objects and the one to get one by ID"""

                                                                
        only_in_obj1 = [ i for i in getAllFunc(self.obj1) if not i in getAllFunc(self.obj2) ]
        only_in_obj2 = [ i for i in getAllFunc(self.obj2) if not i in getAllFunc(self.obj1) ]

                                                                  
                                                                                                
                                                                                                
                                                       

        return (only_in_obj1, only_in_obj2)

    def getDifferencesIn(self, getAllFunc):
        """ Polymorphic method to get the differences between the list of objects on a ModelObject.
        Pass the ObjectDiff class, the unbound method to get all the objects and the one to get one by ID"""

                                                                
        only_in_obj1 = [ i for i in getAllFunc(self.obj1) if not i in getAllFunc(self.obj2) ]
        only_in_obj2 = [ i for i in getAllFunc(self.obj2) if not i in getAllFunc(self.obj1) ]

        return only_in_obj1, only_in_obj2

class HostDiff(ModelObjectDiff):
    """A container for all the differences between two hosts"""
    def __init__(self, h1, h2):
        super(HostDiff, self).__init__(h1, h2)

        obj1_only, obj2_only = self.getDifferencesIn(h1.__class__.getAllInterfaces) 
        if len(obj1_only):
            self.only_in_obj1.update({"Interfaces": obj1_only})
        if len(obj2_only):
            self.only_in_obj2.update({"Interfaces": obj2_only})

        obj1_only, obj2_only = self.getDifferencesIn(h1.__class__.getAllServices)
        if len(obj1_only): 
            self.only_in_obj1.update({"Services": obj1_only})
        if len(obj2_only):
            self.only_in_obj2.update({"Services": obj2_only})

        obj1_only, obj2_only = self.getDifferencesIn(h1.__class__.getVulns)
        if len(obj1_only): 
            self.only_in_obj1.update({"Vulns": obj1_only})
        if len(obj2_only):
            self.only_in_obj2.update({"Vulns": obj2_only})

        obj1_only, obj2_only = self.getDifferencesIn(h1.__class__.getAllApplications) 
        if len(obj1_only):
            self.only_in_obj1.update({"Apps": obj1_only})
        if len(obj2_only):
            self.only_in_obj2.update({"Apps": obj2_only})

class InterfaceDiff(ModelObjectDiff):
    pass

