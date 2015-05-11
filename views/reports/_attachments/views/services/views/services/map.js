// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type=="Service"){
        emit(doc._id, {
            "_id": doc._id,
            "_rev": doc._rev,
            "description": doc.description,
            "metadata": doc.metadata,
            "name": doc.name,
            "owned": doc.owned,
            "owner": doc.owner,
            "parent": doc.parent,
            "ports": doc.ports,
            "protocol": doc.protocol,
	        "status": doc.status,
	        "version": doc.version
        });
    }
}
