#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''

from __future__ import with_statement
try:
    import pysvn
except ImportError:
    print "[-] Python module pySVN was not found in the system, please install it and try again"
    print "ex: sudo apt-get install python-svn"
import os
import re
import traceback
import subprocess
from model import api

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()

__author__     = "Facundo de Guzmán, Esteban Guillardoy"
__copyright__  = "Copyright 2011, Faraday Project"
__credits__    = ["Facundo de Guzmán", "Esteban Guillardoy"]
__license__    = "GPL"
__version__    = "1.0.0"
__maintainer__ = "Facundo de Guzmán"
__email__      = "fdeguzman@ribadeohacklab.com.ar"
__status__     = "Development"

"""
Just to keep in mind. Persistence model in filesystem looks like this:
%PERSISTENCE%/           (default: $HOME/.faraday/persistence/)
        workspace_name/
            categories.xml
            host_id1.xml
            host_id2.xml
            host_id3.xml
                        

IMPORTANT: The svn repository must be manually created by a user.
Faraday will work with svn urls doing a checkout the first time and updating &
commiting later.

XXX: The checkout will be done only if "$HOME/.faraday/persistence/.svn/" directory doesn't
exist, by using the URL provided in the preferences.

"""

class DataManagerException(Exception):
    pass

class DataManager(object):
    def __init__(self, url="", username=None, password=None, memory_threshold=10):
                                                                            
        self.memory_threshold = memory_threshold

        self.url      = url
        self.username = username
        self.password = password

        self.persistence_path = CONF.getPersistencePath()                            

        self._client = pysvn.Client()
        self._client.callback_get_login = self.get_login
        self._client.callback_get_log_message = self.get_log_message
        self._client.callback_notify = self.callback_notify
        self.enable_notify_callback = False
        self._client.exception_style = 1                                       
                                                                                   
        self._files_update_status = None 
        self._clear_files_update_status()
        try:
            self.checkout()
        except DataManagerException:
            pass
        
    def setup_config(self):
        """
        Get needed information from the configuration
        """
                                               
        pass
        
    def sync(self):
        return self.__sync()

    def resolve(self, path):
        self._client.resolved(path)

    def pullChangeSet(self): 
        self.validate_directory()

        self.__do_cleanup()
        self.__do_update()

        added = self._files_update_status["added"]
        removed = self._files_update_status["removed"]
        changed = self._files_update_status["changed"]
        conflicts = self._files_update_status["conflicted"]
        unversioned = self._files_update_status["unversioned"]

                                                                                                  
        conflicted = self.__get_conflicts_by_revision(conflicts)
        
        return added, removed, changed, conflicted

    def __get_conflicts_by_revision(self, conf_files):
        from glob import glob
        full_conflicts = {}
        for conflicting in conf_files:
                                                                             
                                                                                                        
                                                                                                         
            remote_file = sorted(glob(os.path.join(self.persistence_path, "%s.r*" % conflicting)), reverse=True)[0]
            local_file = os.path.join(self.persistence_path, "%s.mine" % conflicting)
            full_conflicts[conflicting] = (local_file, remote_file)
        return full_conflicts


    def __do_cleanup(self):
        """SVN Cleanup call"""
        api.devlog("[SVN] starting sync")
        self._client.cleanup(self.persistence_path)
        api.devlog("[SVN] clean up done")


    def __do_update(self):
        """SVN Update call"""
        api.devlog("[SVN] update action start")
        self.enable_notify_callback = True
        self._clear_files_update_status()
        revision_up = self._client.update(self.persistence_path, recurse=True)
        api.devlog("[SVN] revision after update %s" % str(revision_up)[23:-2])
        self.enable_notify_callback = False                                         
        api.devlog("[SVN] update action done")
        
    def do_checkin(self):
        try:
            revision_up = revision_commit = self._client.checkin(self.persistence_path,
                                                  log_message="",                                        
                                                  recurse=True)
            api.devlog("[SVN] revision after commit %s" % str(revision_up)[23:-2])
        except pysvn.ClientError, e:
            api.devlog("[SVN] Commit action failed: %s" % str(e))
            for message, code in e.args[1]:
                if code != 155015:
                                                                                   
                    raise


    def __sync(self): 
        self.__do_cleanup()
        self._do_update()

        self._do_checkin()

                                              
        added = self._files_update_status["added"]
        removed = self._files_update_status["removed"]
        changed = self._files_update_status["changed"]
        conflicts = self._files_update_status["conflicted"]
        unversioned = self._files_update_status["unversioned"]
        
        return added, removed, changed, conflicts
    
    def validate_directory(self):
        """
        Checks if the persistence directory has valid svn information, meaning
        that a checkout was made and we are ok to work with it
        """
        try:
                                                                    
            self._client.info(self.persistence_path) 
        except pysvn.ClientError, e:
            raise e
    
    def checkout(self):
        if self.url:
            try:
                self.validate_directory()
                msg = "DataManager: Checkout not necessary"
                api.log(msg, "ERROR")                                              
            except:
                try:
                    self._client.checkout(self.url, self.persistence_path)
                except pysvn.ClientError, e:
                                               
                    for message, code in e.args[1]:
                        api.devlog('Code: %d Message: %s' % (code, message))
                        if code == 155000:
                                                                    
                            p = re.compile("\'(/.*)\'")
                            path = p.search(message)
                            self._client.add(path.groups()[0],
                                             recurse=True,
                                             force=False,
                                             ignore=True)
                    self._client.checkout(self.url, self.persistence_path)
        else:
            msg = "DataManager: SVN url is not defined"
            api.log(msg, "ERROR")
            raise DataManagerException(msg)

    def get_login(self, realm, username, may_save ):
        if self.username is None or self.password is None:
            msg = "[SVN] Datamanager: User or Password is None"
            self.username = self.password = ""                                            
            api.log(msg, "[SVN] ERROR")
                                            
        return True, self.username, self.password, False
    
    def get_log_message(self):
                                                                                     
        return True, ""
    
    def _safeAdd(self, path, dirname=False):
        try:     
            if self._client.info(path) is None:                  
                api.devlog("[SVN] adding path %s to svn" % path)
                self._client.add(path, force=False)
                if not dirname:
                    self._client.propset(prop_name="svn:mime-type", prop_value="application/octet-stream", url_or_path=path)
                return True
            else:
                api.devlog("[SVN] path %s is already in svn. Skipping add" % path)
        except pysvn.ClientError, e:
            api.devlog("[ERROR] [SVN] %s" % e)
            raise e

        return False
            
    def share(self, path):
        """
        Shares all .xml files the path via svn
        """
                    
        self._client.cleanup(self.persistence_path)
        
        api.cleanEvidence()
        
        self._safeAdd(path, dirname=True)
        for root, dirs, files in os.walk(path):
            for file in files:
                                                                           
                if os.path.splitext(file)[1].lower() == ".xml":
                    self._safeAdd(os.path.join(root, file))
                elif os.path.splitext(file)[1].lower() == ".png":
                    self._safeAdd(os.path.join(root, file),True)
    
    def rename(self, old, new):
        """
        Renames/Moves a file or folder
        """
        result = False
        try:
            self._client.move(old, new)
            result = True
            api.devlog("[SVN] moved %s to %s" % (old, new))
        except Exception:
            pass
        
        return result
    
    def remove(self, path):
        """
        Remove path from svn
        """
        try:
            self._client.remove(path)
            api.devlog("[SVN] removed %s from svn" % path)
        except pysvn.ClientError, e:
            api.devlog("[SVN] Error while removing file %s from svn.\n%s" % (path, str(e)))
                                                                   
            try:
                os.remove(path)
            except Exception, e:
                api.devlog("[SVN] Error while removing file %s from filesystem.\n%s" % (path, str(e)))
        
    def callback_notify(self, event):
        """
        Callback method to use with pysvn to be able to determine which
        files were changed in a SVN update
        """
                                                                                 
                                                                                    
                                                       
                                                                                     
                                                           
                                                                                       
                                                
                                                                
                                                           
                                                                                                                
                                                                  
                                                                                      
                                                                                                             
                                                            
                                                                 
                                                                       
        
        if self.enable_notify_callback:          
            path = event["path"]
            action = event["action"]
            content_state = event["content_state"]
            api.devlog("pysvn notify callback called - action: %r - content_state: %r - path: %s" %
                       (action, content_state, path))
            
                                                                         
                                                                
                                                                 
                                                                             
                                         
                                                                             
                                                          

            if event["kind"] == pysvn.node_kind.dir or event["kind"] == pysvn.node_kind.none:
                api.devlog("ignoring, it is directory")
                return                                         
            
            if action not in (pysvn.wc_notify_action.update_add,
                              pysvn.wc_notify_action.update_delete,
                              pysvn.wc_notify_action.update_update,
                              pysvn.wc_notify_action.tree_conflict) :
                api.devlog("ignoring, it is not an update action")
                return

            if action == pysvn.wc_notify_action.update_add:
                self._files_update_status["added"].append(path)
            
            elif action == pysvn.wc_notify_action.update_delete:
                self._files_update_status["removed"].append(path)
                
            if action == pysvn.wc_notify_action.update_update:
                
                if content_state in (pysvn.wc_notify_state.changed,
                                     pysvn.wc_notify_state.merged):
                    self._files_update_status["changed"].append(path)
                elif content_state == pysvn.wc_notify_state.conflicted:
                    self._files_update_status["conflicted"].append(path)

            if action == pysvn.wc_notify_action.tree_conflict:
                self._files_update_status["conflicted"].append(path)
        else:
            api.devlog("pysvn notify callback called but flag disabled... ignoring!")
        
    
    def _clear_files_update_status(self):
        self._files_update_status = {
                                        "added" : [],
                                        "removed" : [],
                                        "changed" : [],
                                        "conflicted": [],
                                        "unversioned": []
                                    }
