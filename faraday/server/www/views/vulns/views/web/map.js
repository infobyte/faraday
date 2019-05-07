// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type == "VulnerabilityWeb"){
        var easeofresolution = "",
        impact = {
            "accountability": false,
            "availability": false,
            "confidentiality": false,
            "integrity": false
        },
        resolution = "";
        if(doc.easeofresolution !== undefined) {
            easeofresolution = doc.easeofresolution;
        }
        if(doc.impact !== undefined) {
            impact = doc.impact;
        }
        if(doc.resolution !== undefined) {
            resolution = doc.resolution;
        }

        var obj = {
            "_rev":          	doc._rev,
            "_attachments":  	doc._attachments,
            "data":         	doc.data,
            "desc":             doc.desc, 
            "easeofresolution": easeofresolution,
            "impact":           impact,
            "metadata":         doc.metadata,
            "name":         	doc.name, 
            "obj_id":          	doc.obj_id,
            "owned":        	doc.owned,
            "owner":        	doc.owner,
            "parent":       	doc.parent, 
            "refs":         	doc.refs,
            "resolution":       resolution,
            "severity":     	doc.severity,
            "type":         	doc.type,
            /*** specific fields of web vulns ***/
            "method":       	doc.method,
            "params":       	doc.params,
            "path":         	doc.path,
            "pname":        	doc.pname,
            "query":        	doc.query,
            "request":      	doc.request,
            "response":     	doc.response,
            "website":      	doc.website
        };
        emit(doc._id, obj);
    }
}
