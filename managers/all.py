#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

import os
from couchdbkit import designer


class ViewsManager(object):
    """docstring for ViewsWrapper"""
    def __init__(self):
        self.vw = ViewsListObject()

    def addView(self, design_doc, workspaceDB):
        designer.push(design_doc, workspaceDB, atomic = False)

    def addViewForFS(self, design_doc, workspaceDB):
        designer.fs.push(design_doc, workspaceDB, encode_attachments = False)

    def getAvailableViews(self):
        return self.vw.get_all_views()

    def getViews(self, workspaceDB):
        views = {}
        result = workspaceDB.all_docs(startkey='_design', endkey='_design0')
        if result:
            for doc in result.all():
                designdoc = workspaceDB.get(doc['id'])
                views.update(designdoc.get("views", []))
        return views

    def addViews(self, workspaceDB, force = False):
        installed_views = self.getViews(workspaceDB)
        for v in self.getAvailableViews():
            if v not in installed_views or force:
                self.addView(v, workspaceDB)


class ViewsListObject(object):
    """ Representation of the FS Views """
    def __init__(self):
        self.views_path = os.path.join(os.getcwd(), "views")
        self.designs_path = os.path.join(self.views_path, "reports", "_attachments", "views")

    def _listPath(self, path):
        flist = filter(lambda x: not x.startswith('.'), os.listdir(path))
        return map(lambda x: os.path.join(path, x), flist)

    def get_fs_designs(self):
        return self._listPath(self.designs_path)

    def get_all_views(self):
        return self.get_fs_designs()
