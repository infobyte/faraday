// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
      if(doc.type=="Vulnerability" || doc.type=="VulnerabilityWeb"){
              emit(doc._id,{"date":doc.metadata.create_time, "status":doc.type, "name":doc.name, "desc":doc.desc, "severity": doc.severity, "parent": doc.parent});
                }
}
