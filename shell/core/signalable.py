'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

                                                
                                                                               
                        
class Signalable(object):
    """a class implementing a signal API similar to the qt's one"""

    def __init__(self, *args):
        super(Signalable, self).__init__(*args)
        self.__connected = {}

    def myconnect(self, signal, callback):
        """connect the given callback to the signal"""
        self.__connected.setdefault(signal, []).append(callback)

    def mydisconnect(self, signal, callback):
        """disconnect the given callback from the signal"""
        self.__connected[signal].remove(callback)

    def myemit(self, signal, args=()):
        """emit the given signal with the given arguments if any"""
        for callback in self.__connected.get(signal, []):
            try:
                callback(*args)
            except Exception:
                import traceback
                traceback.print_exc()
