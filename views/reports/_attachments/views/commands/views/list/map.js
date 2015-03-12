// Faraday Penetration Test IDE
// // Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// // See the file 'doc/LICENSE' for the license information
function(doc) {
    if(doc.type=="CommandRunInformation"){
        key = doc.command + " " + doc.params;
        emit(key, {"startdate": doc.itime, "duration": doc.duration, "hostname": doc.hostname, "user": doc.user, "ip": doc.ip});
    }
}
