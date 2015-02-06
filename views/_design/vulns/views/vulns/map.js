// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type == "Vulnerability"){
        var easeofresolution = "",
        impact = "",
        resolution = "";
        if(doc.easeofresolution == "undefined" || typeof(doc.easeofresolution) == "undefined") {
            easeofresolution = "trivial";
        } else {
            easeofresolution = doc.easeofresolution;
        }
        if(doc.impact == "undefined" || typeof(doc.impact) == "undefined") {
            impact = {
                "accountability": 0,
                "availability": 0,
                "confidentiality": 0,
                "integrity": 0
            };
        } else {
            impact = doc.impact;
        }
        if(doc.resolution == "undefined" || typeof(doc.resolution) == "undefined") {
            resolution = "";
        } else {
            resolution = doc.resolution;
        }

        var obj = {
            "rev":              doc._rev,
            "attachments":      doc._attachments,
            "data":             doc.data,
            "date":             doc.metadata.create_time, 
            "desc":             doc.desc, 
            "easeofresolution": doc.easeofresolution,
            "impact":           doc.impact,
            "meta":             doc.metadata,
            "name":             doc.name, 
            "oid":              doc.obj_id,
            "owned":            doc.owned,
            "owner":            doc.owner,
            "parent":           doc.parent, 
            "refs":             doc.refs,
            "resolution":       doc.resolution,
            "severity":         doc.severity, 
            "type":             doc.type 
        };
        emit(doc._id, obj);
    }
}
