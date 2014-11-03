// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information
function(doc) {
  if(doc.type=="Service"){
      if(doc.parent != 'null' & (doc.status =='open' | doc.status =='running')) { 
          var hid =  doc._id.substring(0, doc._id.indexOf('.'));
          emit(doc.name, 1); 
      }
  }
}
