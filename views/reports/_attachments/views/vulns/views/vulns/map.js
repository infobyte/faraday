// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type == "Vulnerability"){
        var easeofresolution = "trivial",
        impact = {
            "accountability": 0,
            "availability": 0,
            "confidentiality": 0,
            "integrity": 0
        },
        resolution = "";
        if(doc.easeofresolution != "undefined" && typeof(doc.easeofresolution) != "undefined") {
            easeofresolution = doc.easeofresolution;
        }
        if(doc.impact != "undefined" && typeof(doc.impact) != "undefined") {
            impact = doc.impact;
        }
        if(doc.resolution != "undefined" && typeof(doc.resolution) != "undefined") {
            resolution = doc.resolution;
        }

        var obj = {
            "_rev":             doc._rev,
            "_attachments":     doc._attachments,
            "data":             doc.data,
            "desc":             doc.desc, 
            "easeofresolution": easeofresolution,
            "impact":           impact,
            "metadata":         doc.metadata,
            "name":             doc.name, 
            "obj_id":           doc.obj_id,
            "owned":            doc.owned,
            "owner":            doc.owner,
            "parent":           doc.parent, 
            "refs":             doc.refs,
            "resolution":       resolution,
            "severity":         doc.severity, 
            "type":             doc.type 
        };
        emit(doc._id, obj);
    }
}
