// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type=="Host"){
        emit(doc._id, {
            "_id": doc._id,
            "_rev": doc._rev,
            "categories": doc.categories,
            "default_gateway": doc.default_gateway,
            "description": doc.description,
            "metadata": doc.metadata,
            "name": doc.name,
            "os": doc.os,
            "owned": doc.owned,
            "owner": doc.owner
        });
    }
}
