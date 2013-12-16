// Faraday Penetration Test IDE - Community Version
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

function(doc) {
	if(doc.type=="Vulnerability" || doc.type=="VulnerabilityWeb") {
	  var label = "5";
	  var sev = doc.severity;
	  if(sev == "Information") {
	    label = "0";
	  } else if(sev == "Low") {
	    label = "1";
	  } else if(sev == "Medium") {
	    label = "2";
	  } else if(sev == "High") {
	    label = "3";
	  } else if(sev == "Critical") {
	    label = "4";
	  } else if(sev=="") {
	    label = "5";
	  } else if(sev >= 0 && sev <= 4) {
	    label = sev;
	  }
	  emit(label, 1);
	}
}
