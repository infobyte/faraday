// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
  if(doc.type=="Service") {
    emit("services", 1); 
  } else if(doc.type=="Service" && doc.owned == "True") {
    emit("services owned", 1); 
  } else if(doc.type=="Host") {
    emit("hosts", 1);
  } else if(doc.type=="Host" && doc.owned == "True") {
    emit("hosts owned", 1);
  } else if(doc.type=="Interface") {
    emit("interfaces", 1);
  } else if(doc.type=="Note") {
    emit("notes", 1);
  } else if(doc.type=="VulnerabilityWeb" || doc.type=="Vulnerability") {
    if(doc.type=="VulnerabilityWeb") {
      emit("web vulns", 1);
    } else {
      emit("vulns", 1);
    }
    emit("total vulns", 1);
  }
}
