#!/usr/bin/env python2
# -*- coding: utf-8 -*- 
'''
Faraday Penetration Test IDE - Community Version
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import couchdbkit
import model.workspace
import persistence.mappers.data_mappers as dm


source_server = 'http://192.168.10.159:5984'
source_db  = 'fitbit'

# Levanto los servidores 
db_source = couchdbkit.Database("/".join((source_server, source_db)))

# Primero replico para no cagarla
db_source.server.replicate(source_db, '%s-backup' % source_db, create_target = True)
db_dest = couchdbkit.Database("/".join((source_server,
                                    '%s-backup' % source_db)))

# Crear documento 'workspace'
workspace = model.workspace.Workspace('%s-backup' % source_db,
                                    'Migrated Workspace ')
dict_workspace = dm.WorkspaceMapper(None).serialize(workspace) 
db_dest.save_doc(dict_workspace, force_update = True)
types = {}

for document in db_dest.all_docs(include_docs=True):
    # Alter parent id:
    doc = document['doc']
    if not('type' in doc): continue
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
        doc['owned'] = eval(doc['owned'])

        document['doc'] = doc 
        db_dest.save_doc(doc, force_update = True)

    types[doc['type']] = types.get(doc['type'], 0) + 1

print(types)

# modificar parents ids

# modificar command information objects
