// Faraday Penetration Test IDE
// Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
// See the file 'doc/LICENSE' for the license information

function(doc) {
    var parent = "None"
    if (doc.parent) {
        parent = doc.parent
    }
    emit([parent, doc.type], doc._id);
}