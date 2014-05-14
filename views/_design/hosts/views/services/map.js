// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
  if(doc.type=="Service"){
    if(doc.parent != 'null') {
      var hid =  doc._id.substring(0, doc._id.indexOf('.'));
      emit(hid, {"name": doc.name,
			"description": doc.description,
			"protocol": doc.protocol,
			"ports": doc.ports,
			"status": doc.status,
			"owned": doc.owned,
			"hid": hid});
    }
  }
}
