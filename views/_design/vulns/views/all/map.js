// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type == "Vulnerability" || doc.type == "VulnerabilityWeb"){
        var obj = {
            "rev":      doc._rev,
            "desc":     doc.desc, 
            "meta":     doc.metadata,
            "date":     doc.metadata.create_time, 
            "name":     doc.name, 
            "oid":      doc.obj_id,
            "owned":    doc.owned,
            "owner":    doc.owner,
            "parent":   doc.parent, 
            "refs":     doc.refs,
            "severity": doc.severity, 
            "status":   doc.type 
        };
        emit(doc._id, obj);
    }
}
