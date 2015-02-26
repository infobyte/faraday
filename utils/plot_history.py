'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
'''
File: plot_history.py
Author: Dj Foguel
Description: This is a library to graph the MetadataHistoryObject. I'll produce a png until we have this feature attached to the UI.
Dependencies: pydot
'''
import sys
from os.path import join
from os import getcwd
sys.path.append(getcwd())

from model.hosts import Host, HostApplication, Interface, Service
from model.common import ModelObjectVuln, MetadataHistory
import model.controller as controller


def plot_graph():
    import pydot
                                                                                  

                                                                       


                                                                 

    edges_list = []
    metadata = MetadataHistory()

    for obj in ModelObjectIterator():
        history = metadata.getHistory(obj.getID())
        for i in range(len(history) - 1):
            f = lambda x: "%s -> %s" % (obj.getID(), x.update_controller_action)
            edge = (f(history[i]), f(history[i + 1]))
            edges_list.append(edge)

    graph = pydot.graph_from_edges(edges_list, directed=True)

    graph.write_png("/home/danito/.faraday/history.png")


class ModelObjectIterator(object):
    """This should solve the iteration problem over ModelObjects"""
    def __init__(self, **kwarg):
        self._to_visit = []
        self._visited = []
        self._model_controller = controller.ModelController()
        self._model_controller.setPersistDir(dir = "/home/danito/.faraday/persistence/Untitled")
        self._model_controller.loadPersistedData(full = True)
        all_hosts = self._model_controller.getAllHosts()

        self._to_visit.extend(all_hosts)

    def __iter__(self):
        return self

    def next(self):
        next_it = None
        try:
            next_it = self._to_visit.pop()
            if next_it in self._visited:
                raise IndexError("No double visit on ModelObject tree")
        except IndexError:
            raise StopIteration 

        self._visited.append(next_it)
        self._to_visit.extend(self._findFollowers(next_it))
        return next_it

    def _findFollowers(self, model_obj):
        followers = []
        cl_name = model_obj.__class__.__name__
        dispatch_methods = follows[cl_name] 

        for dm in dispatch_methods:
            followers.extend(dm(model_obj))

        return followers


follows = { "Host": [Host.getAllApplications, Host.getAllInterfaces, Host.getAllServices, Host.getVulns],
            "Interface": [Interface.getAllServices, Interface.getVulns],
            "HostApplication": [HostApplication.getAllServices, HostApplication.getVulns],
            "Service": [Service.getAllInterfaces, Service.getAllApplications, Service.getVulns]
            }


if __name__ == '__main__':
                                           

    plot_graph()
