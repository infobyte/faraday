'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''


class ModelObjectDiff(object):
    def __init__(self, objLeft, objRight):
        try:
            if not getattr(objLeft, 'class_signature') == getattr(objRight, 'class_signature'):
                raise Exception("Cannot compare objects of different signature. objLeft (%s) vs objRight (%s)"
                                % (objLeft.class_signature, objRight.class_signature))
        except:
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
        for attrname in self.obj1.publicattrsrefs().keys():
            def info(attr_ref): return attr_ref() if callable(attr_ref) else attr_ref
            prop1 = info(self.obj1.__getattribute__(self.obj1.publicattrsrefs().get(attrname)))
            prop2 = info(self.obj2.__getattribute__(self.obj2.publicattrsrefs().get(attrname)))
            if prop1 != prop2:
                prop_diff[attrname] = (prop1, prop2)

        return prop_diff

    # def getDifferences(self, ObjDiff, getAllFunc, getById):
    #     """ Polymorphic method to get the differences between the list of objects on a ModelObject.
    #     Pass the ObjectDiff class, the unbound method to get all the objects and the one to get one by ID"""

    #     only_in_obj1 = [i for i in getAllFunc(self.obj1) if not i in getAllFunc(self.obj2)]
    #     only_in_obj2 = [i for i in getAllFunc(self.obj2) if not i in getAllFunc(self.obj1)]

    #     return (only_in_obj1, only_in_obj2)

    # def getDifferencesIn(self, getAllFunc):
    #     """ Polymorphic method to get the differences between the list of objects on a ModelObject.
    #     Pass the ObjectDiff class, the unbound method to get all the objects and the one to get one by ID"""
    #     only_in_obj1 = [i for i in getAllFunc(self.obj1) if not i in getAllFunc(self.obj2)]
    #     only_in_obj2 = [i for i in getAllFunc(self.obj2) if not i in getAllFunc(self.obj1)]

    #     return only_in_obj1, only_in_obj2


class MergeStrategy(object):
    @staticmethod
    def solve(old, new):
        raise NotImplementedError("This is an abstract class")


class MergeKeepNew(MergeStrategy):
    @staticmethod
    def solve(old, new):
        return new


class MergeKeepOld(MergeStrategy):
    @staticmethod
    def solve(old, new):
        return old


class MergeSolver(object):
    def __init__(self, strategy):
        if strategy == "new":
            self.strategy = MergeKeepNew
        elif strategy == "old":
            self.strategy = MergeKeepOld
        else:
            raise Exception("Invalid strategy to resolve merges")

    def solve(self, old, new):
        return self.strategy.solve(old, new)
