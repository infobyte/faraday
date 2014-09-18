#!/usr/bin/env python2
# -*- coding: utf-8 -*- 
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import subprocess
import pip
import couchdbkit
import model.workspace
import persistence.mappers.data_mappers as dm
from utils.logs import getLogger
from config.globals import *
logger = getLogger('Updater')

from config.configuration import getInstanceConfiguration
CONF = getInstanceConfiguration()
from utils.user_input import query_yes_no
import sys
import os
import shutil

class Updater(object):
    def doUpdates(self):
        logger.info('Removing old pyc files')
        subprocess.call(['find', '.', '-name', '*.pyc', '-delete'])
        logger.info('Pulling latest Github Master copy')
        if query_yes_no('Proceed?', 'yes'):
            subprocess.call(['git', 'pull'])
        logger.info('Checking qt3 libs'):
        for name in ['libqt.so', 'libqt.so.3', 'libqt.so.3.3', 'libqt.so.3.3.8']:
            qt_path = '/usr/local/qt/lib/'
            lib_path = '/usr/local/lib/'
            if os.path.exists(os.path.join(qt_path, name)):
                if not os.path.exists(os.path.join(lib_path, name)):
                    shutil.copy(os.path.join(qt_path, name), os.path.join(lib_path, name))
            else:
                logger.error("You should run the install.sh first")
                sys.exit(-1)
        logger.info('Installing missing dependencies in pip')
        pip.main(['install', '-r', CONST_REQUIREMENTS_FILE, '--user'])
        logger.info('Upgrading DBs to latest version')
        DB().run() 

class Update(object):
    pass

class DB(Update): 
    def __init__(self):
        pass

    def update_db(self, db_name):
        if 'backup' in db_name:
            logger.info('Database [%s] is a backup, ignoring' % db_name)
            
        source_server = CONF.getCouchURI()
        # Levanto los servidores 
        db_source = couchdbkit.Database("/".join((source_server, db_name)))

        # Primero replico para no cagarla
        logger.info('Creating db backup: %s' % ('%s-backup' % db_name))
        db_source.server.replicate(db_name, '%s-backup' % db_name, create_target = True)
        import time
        time.sleep(1)
        db_bkp = couchdbkit.Database("/".join((source_server,
                                            '%s-backup' % db_name)))
        if db_source.doc_exist(db_name): 
            logger.info('DB: [%s] Already had suffer migration' % db_name)
            return

        # Crear documento 'workspace'
        logger.info('Creating workspace document')
        workspace = model.workspace.Workspace(db_name,
                                            'Migrated Workspace ')

        dict_workspace = dm.WorkspaceMapper(None).serialize(workspace) 
        db_source.save_doc(dict_workspace, force_update = True)
        types = {}

        logger.info('Updating modelobject documents')
        for document in db_source.all_docs(include_docs=True): 
            # Alter parent id:
            doc = document['doc']
            if not('type' in doc):
                continue
            if doc['type'] == 'CommandRunInformation':
                # Should set the workspace here!
                continue 
            elif doc['type'] == 'Workspace':
                # Already modified
                continue
            else: 
                # Modify the parent ID
                parent = doc['parent']
                if parent == 'None' or parent == '':
                    parent = None
                else:
                    l_parent = doc['_id'].split('.')[:-1]
                    parent = '.'.join(l_parent) 
                doc['parent'] = parent
                if doc['owned'] == '':
                    doc['owned'] == False
                else: 
                    doc['owned'] = eval(doc['owned'])

                document['doc'] = doc 
                db_source.save_doc(doc, force_update = True)

            types[doc['type']] = types.get(doc['type'], 0) + 1

        logger.info("Transformed %s objects" % str(types))

    
    def run(self):
        source_server = CONF.getCouchURI()
        if not source_server:
            logger.info("""No DB configuration found.
                    To upgrade your DB please configure a valid CouchDB URI in:
                    ~/.faraday/config/user.xml configuration file.""")
            return

        serv = couchdbkit.Server(source_server)

        logger.info('We are about to upgrade dbs in Server [%s]' % source_server)
        dbs = filter(lambda x: not x.startswith("_") and 'backup' not in x, serv.all_dbs())
        logger.info('Dbs to upgrade: %s' % (', '.join(dbs)))

        if not query_yes_no('Proceed?', 'no'):
            return

        logger.info('Preparing updates on Couchdbs')
        processed = 0
        logger.info('About to upgrade %d dbs' % len(dbs))
        for db_name in dbs:
            logger.info('Updating db %s' % db_name)
            try:
                self.update_db(db_name)
                processed = processed + 1
            except Exception as e:
                logger.error(e) 
            logger.info('Updated DB [%s]. %d remaining' % (db_name, len(dbs) - processed)) 
        logger.info("Update process finish, be kind to review the process.\nBackuped databases won't be accesible") 
