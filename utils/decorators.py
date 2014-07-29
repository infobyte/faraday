'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import restkit.errors
import model

def simple_decorator(decorator):
    '''this decorator can be used to turn simple functions
    into well-behaved decorators, so long as the decorators
    are fairly simple. If a decorator expects a function and
    returns a function (no descriptors), and if it doesn't
    modify function attributes or docstring, then it is
    eligible to use this. Simply apply @simple_decorator to
    your decorator and it will automatically preserve the
    docstring and function attributes of functions to which
    it is applied.'''
    def new_decorator(f):
        g = decorator(f)
        g.__name__ = f.__name__
        g.__doc__ = f.__doc__
        g.__dict__.update(f.__dict__)
        return g
                                                            
                                  
    new_decorator.__name__ = decorator.__name__
    new_decorator.__doc__ = decorator.__doc__
    new_decorator.__dict__.update(decorator.__dict__)
    return new_decorator
 

@simple_decorator
def modify_class_field(func):
    def wrapper(self, *args, **kwargs):
        self.cuca = "eehh"
        return func(self, *args, **kwargs)
    return wrapper


@simple_decorator
def updateLocalMetadata(func):
    def wrapper(self, *args, **kwargs):
        self.updateMetadata()
        return func(self, *args, **kwargs)
    return wrapper

@simple_decorator
def passPermissionsOrRaise(func):
    def wrapper(self, *args, **kwargs):
        self.checkPermissions(op = func.func_name)
        return func(self, *args, **kwargs)
    return wrapper


@simple_decorator
def trap_timeout(func):
    def wrapper(self, *args, **kwargs):
        try:
            if self._lostConnection:
                # REFACTOR
                WorkspacePersister.addPendingAction(self, func, args, kwargs)
            return func(self, *args, **kwargs)
        except restkit.errors.RequestError as req_error:
            self.lostConnectionResolv()
            WorkspacePersister.stopThreads()
            WorkspacePersister.addPendingAction(self, func, args, kwargs)
            WorkspacePersister.notifyPersisterConnectionLost()
            model.api.devlog("Operation [%s] timeout" % func.__name__)
            return func(self, *args, **kwargs)
    return wrapper


