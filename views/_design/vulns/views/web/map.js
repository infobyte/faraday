// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc.LICENSE' for the license information
function(doc. {
    if(doc.type == "VulnerabilityWeb"){
        var obj = {
            "rev":          	doc._rev,
            "attachments":  	doc._attachments,
            "data":         	doc.data,
            "date":         	doc.metadata.create_time, 
            "desc":         	doc.desc, 
            "easeofresolution": doc.easeofresolution,
            "impact":           doc.impact,
            "meta":         	doc.metadata,
            "name":         	doc.name, 
            "oid":          	doc.obj_id,
            "owned":        	doc.owned,
            "owner":        	doc.owner,
            "parent":       	doc.parent, 
            "refs":         	doc.refs,
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
